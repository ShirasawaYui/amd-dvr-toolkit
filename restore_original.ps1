# ============================================================
#  恢复原版 AMDRSServ.exe（撤销 2 字节补丁与清单修改）
#  按当前文件的构建自动选择对应原版：从 backup 目录找 sha 吻合的备份覆盖回去
#  （内置 26.20.15.02 / 26.20.15.07 两代；其他版本会拒绝动作）
#  并用 RSServCmd restart（经临时计划任务，普通权限）重启引擎。
#  仅在需要彻底回到原始状态时使用。
# ============================================================
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '需要管理员权限，正在请求提权（请在 UAC 窗口点“是”）...'
    Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoExit','-NoProfile','-ExecutionPolicy','Bypass','-File', ('"' + $PSCommandPath + '"'))
    exit
}

$target    = 'C:\Program Files\AMD\CNext\CNext\AMDRSServ.exe'
$engineCmd = 'C:\Program Files\AMD\CNext\CNext\RSServCmd.exe'
$backupDir = Join-Path $PSScriptRoot 'backup'
$stateFile = Join-Path $PSScriptRoot 'restore_state.json'
# 已知构建表：按当前文件的 sha 判断属于哪一代，再用该代的原版备份还原。
$builds = @(
    @{ name = '26.20.15.02'; orig = '0f28b30898024e49709f5d90ce64d6616ff2fb71f8822f394eafce05d5e450c9'; patched = '1ae3fcc541677b70ad210370453f7ece4a4b4895e1b173327ab2df8ad88194ba'; fixed = '72099cb617109805d5fb79cc345ee3908bf1ec27c6b728df84ecf0b8f7a5f840' },
    @{ name = '26.20.15.07'; orig = 'ff26b09aaea6ef0fd1154240341ae4a545799af01cef51877617cf8006fc3528'; patched = '0dc22efa5ab621756ed1246abc975abf6a3347183bc06108078320068430447e'; fixed = 'ae4f3058c9ccf1e822b479f5c161d10a886cbc3f973cfd9aeeec4791aa66156e' }
)

function Save-State($obj) { $obj | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $stateFile -Encoding UTF8 }
function Test-Writable {
    try {
        $fs = [IO.File]::Open($target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
        $fs.Close()
        return $true
    } catch { return $false }
}
function Stop-AmdProcs([string[]]$names) {
    foreach ($n in $names) { Get-Process $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
}
function Wait-Writable([int]$times = 6) {
    for ($i = 0; $i -lt $times; $i++) { if (Test-Writable) { return $true }; Start-Sleep -Milliseconds 800 }
    return $false
}
function Ensure-UI {
    if (-not (Get-Process RadeonSoftware -ErrorAction SilentlyContinue)) {
        Write-Host '启动 AMD 软件界面（计划任务 StartCN）...'
        Start-ScheduledTask -TaskName 'StartCN' -ErrorAction SilentlyContinue
        for ($i = 0; $i -lt 20; $i++) {
            if (Get-Process RadeonSoftware -ErrorAction SilentlyContinue) { break }
            Start-Sleep -Seconds 1
        }
    }
}
function Start-EngineTask {
    $tn = 'DvrFixStartEngine'
    try {
        $taskAction = New-ScheduledTaskAction -Execute $engineCmd -Argument 'restart'
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId ($env:COMPUTERNAME + '\' + $env:USERNAME) -LogonType Interactive -RunLevel Limited
        Register-ScheduledTask -TaskName $tn -Action $taskAction -Principal $taskPrincipal -Force | Out-Null
        Start-ScheduledTask -TaskName $tn
        Start-Sleep -Seconds 5
        try { Unregister-ScheduledTask -TaskName $tn -Confirm:$false | Out-Null } catch { }
        return $true
    } catch {
        try { & $engineCmd restart | Out-Null; return $true } catch { return $false }
    }
}

$state = [ordered]@{ time_start = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); action = 'restore_original'; build = $null; backup_used = $null; engine_pid = $null; message = '' }

Write-Host '===== 恢复原版 AMDRSServ.exe =====' -ForegroundColor Cyan
$curSha = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLower()
$build = $null
foreach ($b in $builds) {
    if ($curSha -eq $b.orig -or $curSha -eq $b.patched -or $curSha -eq $b.fixed) { $build = $b; break }
}
if (-not $build) {
    $state.message = 'unknown_build'
    Save-State $state
    Write-Host '当前文件与已知构建均不匹配（可能 AMD 已更新），无法确定该还原哪一代原版。未做任何修改。' -ForegroundColor Red
    Read-Host '按回车关闭'
    exit
}
$origSha = $build.orig
$state.build = $build.name
Write-Host ('当前构建: ' + $build.name)
$orig = $null
foreach ($b in (Get-ChildItem -LiteralPath $backupDir -Filter '*.bak' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)) {
    $h = (Get-FileHash -LiteralPath $b.FullName -Algorithm SHA256).Hash.ToLower()
    if ($h -eq $origSha) { $orig = $b; break }
}
if (-not $orig) {
    $state.message = 'no_valid_backup'
    Save-State $state
    Write-Host ('未找到构建 ' + $build.name + ' 的有效原始备份，未做任何修改。') -ForegroundColor Red
    Read-Host '按回车关闭'
    exit
}

if (-not (Test-Writable)) {
    Write-Host '停止 DVR 引擎...'
    Stop-AmdProcs @('AMDRSServ')
    if (-not (Wait-Writable)) {
        Write-Host '文件仍被占用，同时停止 AMD 界面与相关组件...'
        Stop-AmdProcs @('AMDRSServ', 'RadeonSoftware', 'AMDRSSrcExt', 'amdow')
        [void](Wait-Writable)
    }
}
if (-not (Test-Writable)) {
    $state.message = 'file_locked'
    Save-State $state
    Write-Host '无法写入：文件仍被占用，未做修改。' -ForegroundColor Red
    Ensure-UI
    Read-Host '按回车关闭'
    exit
}

Copy-Item -LiteralPath $orig.FullName -Destination $target -Force
$h2 = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLower()
$state.backup_used = $orig.Name
Write-Host ('已恢复原版: ' + $orig.Name)
Write-Host ('当前 sha256: ' + $h2)
if ($h2 -ne $origSha) {
    $state.message = 'hash_mismatch_after_restore'
    Save-State $state
    Write-Host '恢复后校验不符！请保存本窗口输出。' -ForegroundColor Red
    Read-Host '按回车关闭'
    exit
}
Start-Sleep -Seconds 2
[void](Start-EngineTask)
$p = $null
for ($i = 0; $i -lt 40; $i++) { $p = Get-Process AMDRSServ -ErrorAction SilentlyContinue | Select-Object -First 1; if ($p) { break }; Start-Sleep -Seconds 1 }
if (-not $p) {
    Write-Host '首次启动未见到引擎，再试一次...'
    [void](Start-EngineTask)
    for ($i = 0; $i -lt 30; $i++) { $p = Get-Process AMDRSServ -ErrorAction SilentlyContinue | Select-Object -First 1; if ($p) { break }; Start-Sleep -Seconds 1 }
}
Ensure-UI
if ($p) {
    $state.engine_pid = $p.Id
    $state.message = 'restored_engine_ok'
    Write-Host ('原版已生效，引擎运行中：PID ' + $p.Id) -ForegroundColor Green
} else {
    $state.message = 'restored_engine_missing'
    Write-Host '原版已恢复，但引擎未出现，请保存本窗口输出。' -ForegroundColor Red
}
$state.time_end = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
Save-State $state
Read-Host '按回车关闭'

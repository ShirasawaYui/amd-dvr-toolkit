# ============================================================
#  恢复原版 AMDRSServ.exe（撤销 2 字节补丁与清单修改）
#  按当前文件的构建自动选择对应原版：从 backup 目录找 sha 吻合的备份覆盖回去
#  （构建表见 build_manifest.json，现内置五代 26.20.15.02/.07/.12/.16 与 26.20.29.02；
#    清单未登记的版本会拒绝动作，不会误覆盖）
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
# 规则清单统一从 build_manifest.json 查询（2.0.0：静态只读，无 builds）。
# 清单缺失/坏态/规则版本不支持时拒绝一切动作；恢复目标由 match-backup 现场配对。
$manifestPath = Join-Path $PSScriptRoot 'build_manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath)) {
    Write-Host ('清单缺失（manifest_missing）：' + $manifestPath + '。拒绝动作，不回退硬编码表。') -ForegroundColor Red
    Read-Host '按回车关闭'; exit 1
}
try {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
} catch {
    Write-Host ('清单解析失败（manifest_parse_error）：' + $_.Exception.Message + '。拒绝动作。') -ForegroundColor Red
    Read-Host '按回车关闭'; exit 1
}
$supportedRuleVersions = @('2.0.0')   # 2.0.0 = 滑动窗口通用定位，无构建哈希白名单
if ($supportedRuleVersions -notcontains [string]$manifest.rule_version) {
    Write-Host ('规则版本不支持（unsupported_rule_version）：' + $manifest.rule_version + '。拒绝动作。') -ForegroundColor Red
    Read-Host '按回车关闭'; exit 1
}
# 2.0.0 清单无 builds；恢复目标由 dvr_tool.py match-backup 现场反派生配对。
# 解释器必须与注入入口同策略：逐个试 import pefile，第一个成功的才用。
$py = $null
$candidates = New-Object System.Collections.Generic.List[string]
if ($env:DVR_TOOLKIT_PYTHON) { $candidates.Add($env:DVR_TOOLKIT_PYTHON) }
foreach ($pyName in @('python', 'py', 'python3')) {
    foreach ($c in @(Get-Command $pyName -ErrorAction SilentlyContinue)) {
        if ($c.Source -and -not $candidates.Contains($c.Source)) { $candidates.Add($c.Source) }
    }
}
foreach ($pat in @((Join-Path $env:LOCALAPPDATA 'Programs\Python\Python*\python.exe'),
                   (Join-Path $env:USERPROFILE '.workbuddy\binaries\python\versions\*\python.exe'))) {
    foreach ($c in @(Get-ChildItem -Path $pat -ErrorAction SilentlyContinue)) {
        if (-not $candidates.Contains($c.FullName)) { $candidates.Add($c.FullName) }
    }
}
foreach ($cand in $candidates) {
    $v = & $cand -c "import sys,pefile;print(sys.version.split()[0])" 2>$null
    if ($LASTEXITCODE -eq 0 -and $v) { $py = $cand; break }
}
if (-not $py) {
    Write-Host '未找到可用 Python 解释器（需能 import pefile）。拒绝动作。' -ForegroundColor Red
    Read-Host '按回车关闭'; exit 1
}

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

# 2.0.0：不再靠「当前哈希命中某条构建的三哈希」反查代际。
# 改为把 backup 里每份原版内存派生 patched/fixed，看哪份能推出当前文件。
$matchJson = Join-Path $PSScriptRoot 'restore_match.json'
if (Test-Path -LiteralPath $matchJson) { Remove-Item -LiteralPath $matchJson -Force -ErrorAction SilentlyContinue }
& $py (Join-Path $PSScriptRoot 'dvr_tool.py') match-backup --exe $target --backup-dir $backupDir --manifest $manifestPath --out $matchJson | Out-Null
if (-not (Test-Path -LiteralPath $matchJson)) {
    $state.message = 'match_backup_no_output'
    Save-State $state
    Write-Host '配对检查没有产生结果（Python 依赖或清单异常）。未做任何修改。' -ForegroundColor Red
    Read-Host '按回车关闭'; exit 1
}
$mb = Get-Content -LiteralPath $matchJson -Raw -Encoding UTF8 | ConvertFrom-Json
if ($mb.ambiguous -or -not $mb.orig_sha -or -not $mb.backup_file) {
    $state.message = if ($mb.ambiguous) { 'ambiguous_backup' } else { 'unknown_build' }
    Save-State $state
    Write-Host ('无法唯一配对原版备份（' + $mb.refuse_reason + '）。未做任何修改。') -ForegroundColor Red
    Read-Host '按回车关闭'; exit 1
}
$origSha = $mb.orig_sha.ToLower()
$state.build = $null
Write-Host ('已配对原版: ' + $mb.backup_file + ' | sha=' + $origSha.Substring(0, 12))

$orig = Get-Item -LiteralPath (Join-Path $backupDir $mb.backup_file) -ErrorAction SilentlyContinue
if (-not $orig) {
    $state.message = 'no_valid_backup'
    Save-State $state
    Write-Host ('配对到的备份文件不存在：' + $mb.backup_file + '。未做任何修改。') -ForegroundColor Red
    Read-Host '按回车关闭'; exit 1
}
$hOrig = (Get-FileHash -LiteralPath $orig.FullName -Algorithm SHA256).Hash.ToLower()
if ($hOrig -ne $origSha) {
    $state.message = 'backup_hash_mismatch'
    Save-State $state
    Write-Host '配对备份的实际哈希与登记不符，拒绝覆盖。' -ForegroundColor Red
    Read-Host '按回车关闭'; exit 1
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

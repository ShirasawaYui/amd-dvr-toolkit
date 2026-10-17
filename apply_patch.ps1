# ============================================================
#  AMD 桌面录制静默失败修复补丁（应用 / 更新后重打 二合一）
#  修改内容：AMDRSServ.exe 文件偏移 0x3686B-0x3686C
#           原始字节 08 02（0x208=520 字符） -> 00 01（0x100=256 字符）
#  特性：幂等（已打过则跳过）；字节不符（如 AMD 更新后）则中止不动。
#  流程：备份 -> 停止引擎（必要时连界面）-> 改 2 字节 -> 校验 -> 重启 AMD
# ============================================================
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '需要管理员权限，正在请求提权（请在 UAC 窗口点“是”）...'
    Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoExit','-NoProfile','-ExecutionPolicy','Bypass','-File', ('"' + $PSCommandPath + '"'))
    exit
}

$target = 'C:\Program Files\AMD\CNext\CNext\AMDRSServ.exe'
$offset = 0x3686B
$patchB = [byte[]](0x00, 0x01)
$backupDir = Join-Path $PSScriptRoot 'backup'

function Read-Head6 {
    $fs = [IO.File]::Open($target, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $fs.Position = $offset - 2
        $b = New-Object byte[] 6
        [void]$fs.Read($b, 0, 6)
        return $b
    } finally { $fs.Close() }
}
function Test-Writable {
    try {
        $fs = [IO.File]::Open($target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
        $fs.Close()
        return $true
    } catch { return $false }
}
function Stop-AmdProcs([string[]]$names) {
    foreach ($n in $names) {
        Get-Process $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 2
}
function Wait-Writable([int]$times = 5) {
    for ($i = 0; $i -lt $times; $i++) {
        if (Test-Writable) { return $true }
        Start-Sleep -Milliseconds 800
    }
    return $false
}
function Write-Patch2 {
    $fs = [IO.File]::Open($target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
    try {
        $fs.Position = $offset
        $fs.Write($patchB, 0, 2)
        $fs.Flush()
    } finally { $fs.Close() }
}
function Format-Hex6($b) { return (($b | ForEach-Object { $_.ToString('x2') }) -join ' ') }

Write-Host '===== AMD 录制修复补丁 =====' -ForegroundColor Cyan
Write-Host ('脚本目录: ' + $PSScriptRoot)
if (-not (Test-Path -LiteralPath $target)) {
    Write-Host ("未找到 " + $target + "，中止。") -ForegroundColor Red
    Read-Host '按回车关闭'
    exit
}

$head = Read-Head6
Write-Host ("补丁位当前(6字节): " + (Format-Hex6 $head))

if (($head[2] -eq 0x00) -and ($head[3] -eq 0x01)) {
    Write-Host '已经是补丁状态（00 01），跳过修改。' -ForegroundColor Green
}
elseif (($head[2] -eq 0x08) -and ($head[3] -eq 0x02)) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    $ver = ''
    try { $ver = [string](Get-Item -LiteralPath $target).VersionInfo.FileVersion } catch { $ver = '' }
    if (-not $ver) { $ver = 'unknown' }
    $verInfo = $ver -replace '[\r\n\t]+', ' '
    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
    $bak = Join-Path $backupDir ('AMDRSServ.exe.orig.{0}.bak' -f $ts)
    Write-Host ('备份目标: ' + $bak)
    try {
        Copy-Item -LiteralPath $target -Destination $bak -Force -ErrorAction Stop
    } catch {
        Write-Host ('备份失败：' + $_.Exception.Message) -ForegroundColor Red
        Write-Host '未做任何修改（引擎与文件均未动）。请保存本窗口输出。' -ForegroundColor Red
        Read-Host '按回车关闭'
        exit
    }
    $shaOrig = (Get-FileHash -LiteralPath $bak -Algorithm SHA256).Hash
    Write-Host ('已备份: ' + $bak)
    Write-Host ('原始 sha256: ' + $shaOrig)
    Add-Content -LiteralPath (Join-Path $backupDir 'backup_info.txt') -Value ('orig    {0}  version={1}  sha256={2}' -f $ts, $verInfo, $shaOrig)

    if (Get-Process AMDRSServ -ErrorAction SilentlyContinue) { Write-Host '停止 DVR 引擎...' }
    Stop-AmdProcs @('AMDRSServ')
    $locked = $true
    if (Wait-Writable) { $locked = $false }
    if ($locked) {
        Write-Host '文件仍被占用，同时停止 AMD 界面与相关组件...'
        Stop-AmdProcs @('AMDRSServ', 'RadeonSoftware', 'AMDRSSrcExt', 'amdow')
        if (Wait-Writable) { $locked = $false }
    }
    if ($locked) {
        Stop-AmdProcs @('AMDRSServ')
        if (Wait-Writable) { $locked = $false }
    }

    if ($locked) {
        Write-Host '无法写入：文件仍被占用。补丁未应用。' -ForegroundColor Red
    }
    else {
        try {
            Write-Patch2
            $head2 = Read-Head6
            Write-Host ("校验(6字节): " + (Format-Hex6 $head2))
            if (($head2[2] -eq 0x00) -and ($head2[3] -eq 0x01)) {
                $shaNew = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
                Write-Host '补丁写入成功：08 02 -> 00 01' -ForegroundColor Green
                Write-Host ('补丁后 sha256: ' + $shaNew)
                Add-Content -LiteralPath (Join-Path $backupDir 'backup_info.txt') -Value ('patched {0}  sha256={1}' -f $ts, $shaNew)
            }
            else {
                Write-Host '写入后校验不符！请勿反复重试，请保存本窗口输出。' -ForegroundColor Red
            }
        }
        catch {
            Write-Host ('写入异常: ' + $_.Exception.Message) -ForegroundColor Red
        }
    }
}
else {
    Write-Host '补丁位字节与预期不符（可能 AMD 已更新程序）。未做任何修改，请保存本窗口输出。' -ForegroundColor Red
}

Write-Host ''
Write-Host '重启 AMD 软件与 DVR 引擎...'
& (Join-Path $PSScriptRoot 'start_amd.ps1')

Write-Host ''
Write-Host '处理完成。请保存本窗口输出。' -ForegroundColor Cyan
Read-Host '按回车关闭'

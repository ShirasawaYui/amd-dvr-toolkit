# 解卡脚本启动器（录制“静默失败”时使用）
# 原理：在调试会话内把类名读取长度临时从 520 改为 256，强制打通一次场景转换；
#       不改磁盘文件、不伪装消息；命中后自动分离。原理见仓库 README。
param([string]$CdbPath)
Set-Location -LiteralPath $PSScriptRoot

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '需要管理员权限，正在请求提权（请在 UAC 窗口点“是”）...'
    Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoExit','-NoProfile','-ExecutionPolicy','Bypass','-File', ('"' + $PSCommandPath + '"'))
    exit
}

Write-Host '===== DVR 录制解卡（保底手段） =====' -ForegroundColor Cyan
Write-Host '适用：点击录制后静默无反应（引擎/整机重启后的第一击可能遇到）。'
Write-Host '若当前录制正常，无需运行；误运行可 Ctrl+C 退出。'
Write-Host ''

$engine = Get-Process AMDRSServ -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $engine) {
    Write-Host 'DVR 引擎未在运行：请先双击“启动AMD软件.cmd”，稍后再运行本脚本。' -ForegroundColor Red
    Read-Host '按回车关闭'
    exit
}
if (Get-Process cdb -ErrorAction SilentlyContinue) {
    Write-Host '已有调试器(cdb)在运行：请先到它的窗口按 Ctrl+C，再依次输入  bc *  回车、qd  回车，然后重试。' -ForegroundColor Red
    Read-Host '按回车关闭'
    exit
}

# 调试器查找顺序：-CdbPath 参数 > 环境变量 DVR_CDB_PATH > 同级的
# windbg-portable\amd64\cdb.exe（本仓库不包含调试器，仅兼容既有部署）> PATH 中的 cdb。
# cdb 可通过 Microsoft Store 的「WinDbg」或 Windows SDK Debugging Tools 获取。
$cdbCandidates = @()
if ($CdbPath) { $cdbCandidates += $CdbPath }
if ($env:DVR_CDB_PATH) { $cdbCandidates += $env:DVR_CDB_PATH }
$cdbCandidates += (Join-Path (Split-Path -Parent $PSScriptRoot) 'windbg-portable\amd64\cdb.exe')
$cdbCandidates += (Join-Path $PSScriptRoot 'windbg-portable\amd64\cdb.exe')
$cdbCmd = Get-Command cdb -ErrorAction SilentlyContinue
if ($cdbCmd) { $cdbCandidates += $cdbCmd.Source }
$cdb = $cdbCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
if (-not $cdb) {
    Write-Host '未找到调试器 cdb.exe。' -ForegroundColor Red
    Write-Host '请通过 Microsoft Store 安装「WinDbg」（内含 cdb），或安装 Windows SDK 的 Debugging Tools；'
    Write-Host '也可用 -CdbPath 参数或环境变量 DVR_CDB_PATH 指定 cdb.exe 路径。'
    Read-Host '按回车关闭'
    exit
}

$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = Join-Path $PSScriptRoot ('unblock_{0}.log' -f $ts)
Write-Host ('引擎 PID: ' + $engine.Id)
Write-Host ''
Write-Host '【操作】出现 TRACE_READY_CLICK_RECORD_ONCE 后：只点一次录制；'
Write-Host '        若开始录制，几秒后正常停止。结束后调试器会自动分离。'
Write-Host '【撤销】想中途退出：按 Ctrl+C，然后依次输入  bc *  回车、 qd  回车。'
Write-Host ''

& $cdb -pd -G -nosqm -sins -y $PSScriptRoot -logou $log -cf (Join-Path $PSScriptRoot 'trace_dvr2.cdb') -p $engine.Id

Write-Host ''
Write-Host ('已结束。过程日志：' + $log) -ForegroundColor Green
Read-Host '按回车关闭'

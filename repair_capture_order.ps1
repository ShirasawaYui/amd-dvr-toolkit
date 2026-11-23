param(
    [int]$EngineWaitSec = 15,
    [int]$ReadySec = 15,
    [int]$UiWaitSec = 90,
    [switch]$NoPause
)
# 修复「点录制无反应」——启动顺序校正
# 背景（2026-11-23 实测，驱动 26.20.29.02）：
#   AMD 用两个登录计划任务分别拉起界面与引擎：StartCN(cncmd startwithdelay) / StartDVR(RSServCmd)
#   两者同秒触发，但引擎就绪耗时波动大（实测 38 / 81 / 95 秒），界面约 23-37 秒。
#   只要「界面启动那一刻引擎尚未就绪」，界面即进入永久不可用：按钮可点、点了不发命令，
#   此后无论换多少次引擎都救不回来（实测连杀 4 次引擎均无效），必须界面与引擎一起重来。
# 本脚本做四件事：①关界面 ②关引擎 ③等引擎自己回来并等它就绪 ④再开界面
# 不读 dvrlog、不改注册表、不需要管理员权限。
#
# 启动界面必须经 cncmd（2026-11-23 20:22 实证）：
#   正常界面的命令行是 "Radeonsoftware.exe" atlogon，并带一个子进程 cncmd.exe "watch <pid>"；
#   而直接 Start-Process RadeonSoftware.exe 得到的实例无参数、无 cncmd watch，
#   界面能显示、按钮能点，但点下去引擎侧连一条录制请求都收不到（静默失效）。
#   因此本脚本改用 cncmd.exe startwithdelay（与开机自启的 StartCN 任务同一条路径）。
#
# 健康判据（2026-11-23 20:30 修正）：
#   不要用「主窗口是否可见」当判据。正常启动后界面停在系统托盘，Qt 主窗口处于隐藏状态，
#   MainWindowHandle 恒为 0（实测该进程 9 个顶层窗口全部 vis=False），原逻辑会一直干等，
#   直到用户手工双击托盘图标才跳出。
#   真正决定录制可用的是「界面进程存在 + cncmd.exe watch <pid> 子进程已建立」——
#   cncmd 二进制中该分支会执行 RSServCmd.exe make dvr hide_ui，建立界面与 DVR 引擎的控制通道。
#   判据全部在后台完成，界面留在托盘不动。
#
# 不要主动唤出界面窗口（2026-11-23 20:35 实测）：
#   cncmd.exe show 能把托盘里的界面显示出来（2 秒、不新建实例），但会让界面**变成英文**；
#   而脚本启动后用户自己双击托盘打开的是**中文**。故本脚本不调用 show，也不调用
#   restartandshow / restart，界面窗口一律交由用户从托盘打开。

$ErrorActionPreference = 'Stop'

$amdDir   = 'C:\Program Files\AMD\CNext\CNext'
$engineExe = Join-Path $amdDir 'AMDRSServ.exe'
$uiExe     = Join-Path $amdDir 'RadeonSoftware.exe'
$servCmd   = Join-Path $amdDir 'RSServCmd.exe'
$cncmd     = Join-Path $amdDir 'cncmd.exe'

function Say($msg, $color = 'Gray') { Write-Host ('   ' + $msg) -ForegroundColor $color }
function Head($msg) { Write-Host ''; Write-Host $msg -ForegroundColor Cyan }

if (-not (Test-Path $engineExe)) {
    Write-Host ('找不到引擎文件：' + $engineExe) -ForegroundColor Red
    if (-not $NoPause) { Read-Host '按回车退出' | Out-Null }
    exit 1
}

Write-Host '===== 修复「点录制无反应」：启动顺序校正 =====' -ForegroundColor Cyan
Say '只重启 AMD 界面与 DVR 引擎，不改文件、不改注册表、不需要管理员权限'
Say '若正在录制，请先停止录制再继续'

# ---------- 1 现状 ----------
Head '1) 当前状态'
$uiNow = @(Get-Process -Name 'RadeonSoftware','cncmd','SplashWindow' -ErrorAction SilentlyContinue)
$enNow = @(Get-Process -Name 'AMDRSServ' -ErrorAction SilentlyContinue)
if ($uiNow.Count -eq 0) { Say '界面进程：无' } else { Say ('界面进程：' + (($uiNow | ForEach-Object { "$($_.ProcessName)($($_.Id))" }) -join '、')) }
if ($enNow.Count -eq 0) { Say '引擎进程：无' } else { Say ('引擎进程：' + (($enNow | ForEach-Object { "AMDRSServ($($_.Id))" }) -join '、')) }

# ---------- 2 关界面 ----------
Head '2) 关闭 AMD 界面（必须先于引擎，否则界面会立刻把引擎拉回来）'
foreach ($p in $uiNow) {
    try {
        Stop-Process -Id $p.Id -Force -Confirm:$false -ErrorAction Stop
        Say ('已结束 ' + $p.ProcessName + '(' + $p.Id + ')')
    } catch {
        Say ('未能结束 ' + $p.ProcessName + '(' + $p.Id + ')：' + $_.Exception.Message) 'Yellow'
    }
}
Start-Sleep -Seconds 2
$uiLeft = @(Get-Process -Name 'RadeonSoftware','cncmd','SplashWindow' -ErrorAction SilentlyContinue)
if ($uiLeft.Count -gt 0) {
    Say ('注意：仍有界面进程未退出：' + (($uiLeft | ForEach-Object { $_.ProcessName }) -join '、')) 'Yellow'
} else {
    Say '界面已全部关闭'
}

# ---------- 3 关引擎 ----------
Head '3) 关闭 DVR 引擎'
$enNow = @(Get-Process -Name 'AMDRSServ' -ErrorAction SilentlyContinue)
if ($enNow.Count -eq 0) {
    Say '引擎本未运行，直接进入拉起阶段'
} else {
    foreach ($p in $enNow) {
        try { Stop-Process -Id $p.Id -Force -Confirm:$false -ErrorAction Stop; Say ('已结束 AMDRSServ(' + $p.Id + ')') }
        catch { Say ('未能结束 AMDRSServ(' + $p.Id + ')：' + $_.Exception.Message) 'Yellow' }
    }
}
Start-Sleep -Milliseconds 500

# ---------- 4 等引擎回来 ----------
Head '4) 等待引擎重新启动'
Say '通常由 AMD Crash Defender Service 在 0.1-1 秒内自动拉起'
$newEngine = $null
$deadline = (Get-Date).AddSeconds($EngineWaitSec)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 300
    $c = @(Get-Process -Name 'AMDRSServ' -ErrorAction SilentlyContinue)
    if ($c.Count -gt 0) { $newEngine = $c[0]; break }
}

if (-not $newEngine) {
    Say ('守护未在 ' + $EngineWaitSec + ' 秒内拉起，改为主动调用 RSServCmd start') 'Yellow'
    if (Test-Path $servCmd) {
        try { Start-Process -FilePath $servCmd -ArgumentList 'start' -WindowStyle Hidden | Out-Null } catch { }
    }
    $deadline = (Get-Date).AddSeconds($EngineWaitSec)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 300
        $c = @(Get-Process -Name 'AMDRSServ' -ErrorAction SilentlyContinue)
        if ($c.Count -gt 0) { $newEngine = $c[0]; break }
    }
}

if (-not $newEngine) {
    Write-Host ''
    Write-Host ('失败：引擎在 ' + $EngineWaitSec + ' 秒内未能启动') -ForegroundColor Red
    Say '可能原因：AMD Crash Defender Service 被停用，且 RSServCmd 启动失败'
    Say '请检查服务中「AMD Crash Defender Service」是否为「正在运行 / 自动」'
    Say '或直接重启电脑后再试'
    if (-not $NoPause) { Read-Host '按回车退出' | Out-Null }
    exit 2
}

Say ('引擎已启动：AMDRSServ(' + $newEngine.Id + ')  启动时间 ' + $newEngine.StartTime.ToString('HH:mm:ss'))

# ---------- 5 等就绪 ----------
Head ('5) 等待引擎就绪（' + $ReadySec + ' 秒，实测 Instant Replay 在 1-2 秒内完成）')
for ($i = $ReadySec; $i -gt 0; $i--) {
    if (-not (Get-Process -Id $newEngine.Id -ErrorAction SilentlyContinue)) {
        Write-Host ''
        Write-Host '失败：等待期间引擎进程消失了（可能反复崩溃），已中止' -ForegroundColor Red
        if (-not $NoPause) { Read-Host '按回车退出' | Out-Null }
        exit 3
    }
    Write-Host ("   剩余 {0} 秒" -f $i) -ForegroundColor DarkGray
    Start-Sleep -Seconds 1
}
Write-Host ''
Say '引擎已就绪'

# ---------- 6 开界面（必须经 cncmd，直启 exe 会拿不到 DVR 控制通道）----------
Head '6) 启动 AMD 界面（经 cncmd startwithdelay，与开机自启同一条路径）'
Say '实测：直接启动 RadeonSoftware.exe 时界面能显示，但录制按钮静默失效（缺 cncmd watch 关系）'
$uiLaunched = $false
if (Test-Path $cncmd) {
    try {
        Start-Process -FilePath $cncmd -ArgumentList 'startwithdelay' -WorkingDirectory $amdDir | Out-Null
        Say '已调用：cncmd.exe startwithdelay'
        $uiLaunched = $true
    } catch {
        Say ('cncmd 调用失败：' + $_.Exception.Message) 'Yellow'
    }
}
if (-not $uiLaunched) {
    Say '回退：直接启动界面进程（可能仍无法录制，建议手动从开始菜单打开）' 'Yellow'
    try {
        Start-Process -FilePath $uiExe -WorkingDirectory $amdDir | Out-Null
        Say ('已启动：' + $uiExe)
    } catch {
        Write-Host ('启动界面失败：' + $_.Exception.Message) -ForegroundColor Red
        if (-not $NoPause) { Read-Host '按回车退出' | Out-Null }
        exit 4
    }
}

# 判据改为「进程 + cncmd watch」：界面正常停在托盘，主窗口本就不可见（见文件头说明）
Say ('等待界面进程与 cncmd watch 关系建立（最多 ' + $UiWaitSec + ' 秒）')
$deadline = (Get-Date).AddSeconds($UiWaitSec)
$uiPid = 0
$watched = $false
$lastLeft = -1
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
    $u = Get-Process -Name 'RadeonSoftware' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $u) {
        $left = [int]($deadline - (Get-Date)).TotalSeconds
        if ($left -ne $lastLeft) {
            $lastLeft = $left
            Write-Host ("   剩余 {0} 秒：等待界面进程出现……" -f $left) -ForegroundColor DarkGray
        }
        continue
    }
    if ($uiPid -eq 0) {
        $uiPid = $u.Id
        Write-Host ''
        Say ('界面进程已出现：RadeonSoftware(' + $uiPid + ')，等待 cncmd watch 建立')
    }
    $w = @(Get-CimInstance Win32_Process -Filter "Name='cncmd.exe'" -ErrorAction SilentlyContinue |
           Where-Object { $_.CommandLine -like ('*watch ' + $uiPid + '*') })
    if ($w.Count -gt 0) { $watched = $true; break }
}
Write-Host ''

# 不主动唤出窗口：cncmd show 会把界面切成英文，用户双击托盘打开则是中文（见文件头）
if ($watched) {
    Say '界面已停在系统托盘（正常状态，未主动弹出以免界面语言变英文）'
}

Head '===== 完成 ====='
if ($uiPid -eq 0) {
    Say ('界面进程在 ' + $UiWaitSec + ' 秒内未出现，请手动从开始菜单打开 AMD 软件') 'Yellow'
} elseif ($watched) {
    Say ('界面已就绪（PID ' + $uiPid + '，cncmd watch 已建立）') 'Green'
    Say '需要操作界面时，双击系统托盘的 AMD 图标打开（这样打开是中文界面）'
    Say '也可以用托盘右键菜单直接开始录制'
} else {
    Say ('界面进程已出现（PID ' + $uiPid + '），但未检测到 cncmd watch —— 录制很可能仍失效') 'Yellow'
    Say '请关掉 AMD 软件，再手动从开始菜单打开一次（不要直接双击 RadeonSoftware.exe）' 'Yellow'
}
Say ''
Say '请点 1 次录制、约 10 秒：'
Say '  · 成功 → 问题已解决，可正常使用'
Say '  · 仍无反应 → 可能不是启动顺序问题，改跑「注入引擎修复补丁.cmd」检查补丁是否失效'
Say '  · 若日志出现 Failed to send scene conversion → 补丁失效，跑「注入引擎修复补丁.cmd」后重启电脑'

if (-not $NoPause) { Write-Host ''; Read-Host '按回车退出' | Out-Null }

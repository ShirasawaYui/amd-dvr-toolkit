# ============================================================

#  AMD DVR 修复 v2：2 字节补丁 + 清单 uiAccess 修复，一步完成

#  ------------------------------------------------------------

#  说明：旧版曾用「StartDVR 计划任务」等待引擎启动，实测该任务不能拉起

#  缺失的引擎；本版改用 RSServCmd restart（引擎缺席时也能拉起，形态与

#  正常引擎一致）。

#  流程：状态检查 -> 必要时停进程解锁（界面会瞬时重拉引擎，需连界面

#        一起停）-> 等长改写（文件大小不变）-> 经临时计划任务以普通

#        权限执行 RSServCmd restart -> 校验引擎存活；失败自动回滚。

#  幂等：已修复则跳过改写；状态不符（如 AMD 更新）则不动并说明退出。

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

# Python 解释器：依次尝试 PATH 中的 python / py / python3；
# 也可在此直接写死你的 python.exe 路径（需 Python 3.8+，pefile 为可选依赖）。
$py        = $null
foreach ($pyName in @('python', 'py', 'python3')) {
    $pyCmd = Get-Command $pyName -ErrorAction SilentlyContinue
    if ($pyCmd) { $py = $pyCmd.Source; break }
}
if (-not $py) {
    Write-Host '未找到 Python 解释器：请安装 Python 3 并加入 PATH，或在本脚本顶部写死 $py 路径。' -ForegroundColor Red
    Read-Host '按回车关闭'
    exit
}

$pyScript  = Join-Path $PSScriptRoot 'patch_manifest.py'

$backupDir = Join-Path $PSScriptRoot 'backup'

$stateFile = Join-Path $PSScriptRoot 'last_fix_state.json'

$resultPy  = Join-Path $PSScriptRoot 'last_fix_edit.json'

# 原版 sha 不硬编码：见步骤 0（由构建表按当前文件自动识别）。



$result = [ordered]@{

    time_start    = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    action        = 'fix_v2'

    initial_state = $null

    edit          = $null

    steps         = $null

    ui_stopped    = $false

    engine_pid    = $null

    engine_alive  = $false

    rollback      = $false

    final_engine  = $null

    latest_log    = $null

    message       = ''

}

function Save-State {

    $result.time_end = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $stateFile -Encoding UTF8

}

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

    for ($i = 0; $i -lt $times; $i++) {

        if (Test-Writable) { return $true }

        Start-Sleep -Milliseconds 800

    }

    return $false

}

function Get-LatestLog {

    $d = Join-Path $env:LOCALAPPDATA 'AMD\CN'

    $f = Get-ChildItem -LiteralPath $d -Filter 'dvrlog*.txt' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if ($f) { return $f.Name }

    return $null

}

function Wait-Engine([int]$seconds = 40) {

    for ($i = 0; $i -lt $seconds; $i++) {

        $p = Get-Process AMDRSServ -ErrorAction SilentlyContinue | Select-Object -First 1

        if ($p) { return $p }

        Start-Sleep -Seconds 1

    }

    return $null

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

    # 经临时计划任务（RunLevel=Limited，普通权限）执行 RSServCmd restart，

    # 引擎形态与系统正常启动一致；失败时退化为直接调用。

    $tn = 'DvrFixStartEngine'

    try {

        $taskAction = New-ScheduledTaskAction -Execute $engineCmd -Argument 'restart'

        $taskPrincipal = New-ScheduledTaskPrincipal -UserId ($env:COMPUTERNAME + '\' + $env:USERNAME) -LogonType Interactive -RunLevel Limited

        Register-ScheduledTask -TaskName $tn -Action $taskAction -Principal $taskPrincipal -Force | Out-Null

        Start-ScheduledTask -TaskName $tn

        Start-Sleep -Seconds 5

        try { Unregister-ScheduledTask -TaskName $tn -Confirm:$false | Out-Null } catch { }

        Write-Host '已通过临时计划任务触发引擎启动（RSServCmd restart，普通权限）。'

        return $true

    } catch {

        Write-Host ('临时任务方式未成功（' + $_.Exception.Message + '），改用直接调用兜底...')

        try {

            & $engineCmd restart | Out-Null

            return $true

        } catch {

            Write-Host ('直接调用也失败：' + $_.Exception.Message)

            return $false

        }

    }

}

function Try-Start-Engine {

    if (Get-Process AMDRSServ -ErrorAction SilentlyContinue) { return $true }

    [void](Start-EngineTask)

    if (Wait-Engine 40) { return $true }

    Write-Host '首次启动未见到引擎，再试一次...'

    [void](Start-EngineTask)

    if (Wait-Engine 30) { return $true }

    return $false

}



Write-Host '===== AMD DVR 修复 v2（补丁 + 清单，一步完成）=====' -ForegroundColor Cyan

Write-Host ('脚本目录: ' + $PSScriptRoot)

if (-not (Test-Path -LiteralPath $py))       { Write-Host ('未找到 Python: ' + $py) -ForegroundColor Red; Read-Host '按回车关闭'; exit }

if (-not (Test-Path -LiteralPath $pyScript)) { Write-Host '缺少 patch_manifest.py（应与本脚本同目录）' -ForegroundColor Red; Read-Host '按回车关闭'; exit }



# 0) 识别构建 + 原版备份门槛（原版 sha 由构建表按当前文件给出）

& $py $pyScript --check --out $resultPy | Write-Host

$st0 = Get-Content -LiteralPath $resultPy -Raw -Encoding UTF8 | ConvertFrom-Json

if ($st0.result -eq 'unexpected' -or -not $st0.sha_orig) {

    $result.message = 'aborted_state: ' + $st0.result

    Save-State

    Write-Host '文件状态不符合预期（如 AMD 已更新程序，或检查失败），未做任何修改。请保存本窗口输出。' -ForegroundColor Red

    Read-Host '按回车关闭'

    exit

}

$origSha = $st0.sha_orig

$orig = $null

foreach ($b in (Get-ChildItem -LiteralPath $backupDir -Filter '*.bak' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)) {

    $h = (Get-FileHash -LiteralPath $b.FullName -Algorithm SHA256).Hash.ToLower()

    if ($h -eq $origSha) { $orig = $b; break }

}

if (-not $orig) {

    $result.message = 'no_original_backup'

    Save-State

    Write-Host ('未找到原版备份（backup 目录中没有与构建 ' + $st0.build + ' 吻合的 .bak）。未做任何修改。') -ForegroundColor Red

    Read-Host '按回车关闭'

    exit

}



# 1) 当前状态（只读）

& $py $pyScript --check --out $resultPy | Write-Host

$st = Get-Content -LiteralPath $resultPy -Raw -Encoding UTF8 | ConvertFrom-Json

$result.initial_state = $st.result

$result.build = $st.build

Write-Host ('当前状态: ' + $st.result + ' | ' + $st.message)

if ($st.result -notin @('original_untouched', 'needs_manifest_fix', 'already_fixed')) {

    $result.message = 'aborted_state: ' + $st.result

    Save-State

    Write-Host '文件状态不符合预期（如 AMD 已更新程序，或检查失败），未做任何修改。请保存本窗口输出。' -ForegroundColor Red

    Read-Host '按回车关闭'

    exit

}

if (($st.result -eq 'already_fixed') -and (Get-Process AMDRSServ -ErrorAction SilentlyContinue)) {

    $result.message = 'already_fixed_engine_running'

    $result.engine_pid = (Get-Process AMDRSServ | Select-Object -First 1).Id

    Save-State

    Write-Host ('文件已是修复状态，引擎在运行（PID ' + $result.engine_pid + '），无需动作。') -ForegroundColor Green

    Read-Host '按回车关闭'

    exit

}



# 2) 必要时停进程解锁（界面会把引擎瞬时重拉，故需要时连界面一起停）

if (-not (Test-Writable)) {

    Write-Host '文件被占用，先停止 DVR 引擎...'

    Stop-AmdProcs @('AMDRSServ')

    if (-not (Wait-Writable)) {

        Write-Host '引擎被自动拉起并占用文件（界面监护行为），同时停止界面与相关组件...'

        Stop-AmdProcs @('AMDRSServ', 'RadeonSoftware', 'AMDRSSrcExt', 'amdow')

        [void](Wait-Writable)

        $result.ui_stopped = $true

    }

    if (-not (Test-Writable)) {

        $result.message = 'file_locked'

        Save-State

        Write-Host '无法写入：文件仍被占用，未做修改。将恢复 AMD 界面...' -ForegroundColor Red

        Ensure-UI

        Read-Host '按回车关闭'

        exit

    }

}



# 3) 改写（等长，大小不变）

if ($st.result -ne 'already_fixed') {

    & $py $pyScript --apply --out $resultPy | Write-Host

    $edit = Get-Content -LiteralPath $resultPy -Raw -Encoding UTF8 | ConvertFrom-Json

    $result.edit = $edit.result

    $result.steps = ($edit.steps -join '; ')

    if ($edit.result -ne 'applied') {

        $result.message = 'edit_failed: ' + $edit.result

        Save-State

        Write-Host ('改写未成功：' + $edit.result + '。将恢复 AMD 界面并退出。') -ForegroundColor Red

        Ensure-UI

        Read-Host '按回车关闭'

        exit

    }

    Write-Host ('改写完成：' + $result.steps)

    Write-Host ('改写后 sha256: ' + $edit.sha_after)

    Add-Content -LiteralPath (Join-Path $backupDir 'backup_info.txt') -Value ('fixed {0}  sha256={1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $edit.sha_after)

    Start-Sleep -Seconds 3

}

else {

    Write-Host '文件已是修复状态，跳过改写。'

}



# 4) 启动引擎并校验

$ok = Try-Start-Engine

$enginePid = $null

$alive = $false

if ($ok) {

    $p = Get-Process AMDRSServ -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($p) {

        $enginePid = $p.Id

        Start-Sleep -Seconds 6

        if (Get-Process -Id $enginePid -ErrorAction SilentlyContinue) { $alive = $true }

    }

}

if ($alive) {

    $result.engine_pid = $enginePid

    $result.engine_alive = $true

    $result.final_engine = $enginePid

    $result.latest_log = Get-LatestLog

    $result.message = 'engine_started'

    Save-State

    Write-Host ('引擎已启动且存活：PID ' + $enginePid) -ForegroundColor Green

    if ($result.latest_log) { Write-Host ('最新引擎日志: ' + $result.latest_log) }

    if ($result.ui_stopped) { Write-Host '提示: 本次重启过 AMD 界面；如语言变英文，可在设置中切回。' -ForegroundColor Yellow }

    Write-Host '⚠ 重要：本次启动的引擎带管理员令牌，这个形态下录制不会正常（实测）。' -ForegroundColor Yellow

    Write-Host '   请现在重启电脑，开机后再试录；引擎会自动以普通权限拉起，功能才生效。' -ForegroundColor Yellow

    Write-Host '   （管理员形态引擎的 dvrlog 普通权限也读不到，无法取证。）' -ForegroundColor DarkGray

    Read-Host '按回车关闭'

    exit

}



# 5) 回滚：恢复原版并重启

Write-Host '引擎未能就绪，执行回滚...' -ForegroundColor Yellow

$result.rollback = $true

Stop-AmdProcs @('AMDRSServ')

if (-not (Test-Writable)) {

    Stop-AmdProcs @('AMDRSServ', 'RadeonSoftware', 'AMDRSSrcExt', 'amdow')

    [void](Wait-Writable)

    $result.ui_stopped = $true

}

Copy-Item -LiteralPath $orig.FullName -Destination $target -Force

$h2 = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLower()

Write-Host ('已恢复原版: ' + $orig.Name + ' | sha256=' + $h2)

Start-Sleep -Seconds 2

$ok2 = Try-Start-Engine

if ($ok2) {

    $p2 = Get-Process AMDRSServ -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($p2) {

        $result.final_engine = $p2.Id

        $result.latest_log = Get-LatestLog

        $result.message = 'rolled_back_engine_ok'

        Write-Host ('已回滚，引擎恢复：PID ' + $p2.Id) -ForegroundColor Yellow

    }

}

if ($result.message -eq '') {

    $result.message = 'rolled_back_engine_missing'

    Write-Host '已回滚，但引擎仍未出现，请保存本窗口输出。' -ForegroundColor Red

}

Ensure-UI

Save-State

Write-Host '处理完成，请保存本窗口输出。' -ForegroundColor Cyan

Read-Host '按回车关闭'


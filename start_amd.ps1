# ============================================================
#  启动 AMD 软件（界面）与 DVR 引擎
#  引擎启动使用 RSServCmd restart（StartDVR 计划任务不能可靠拉起缺失的
#  引擎；实测 restart 在引擎缺席时也能启动）。
#  优先经临时计划任务以普通权限执行，失败时直接调用兜底。
# ============================================================
Set-Location -LiteralPath $PSScriptRoot

$engineCmd = 'C:\Program Files\AMD\CNext\CNext\RSServCmd.exe'

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

Ensure-UI
$ui = Get-Process RadeonSoftware -ErrorAction SilentlyContinue
if ($ui) { Write-Host ('AMD 界面运行中 (PID ' + $ui.Id + ')') }
else { Write-Host 'AMD 界面未出现，请稍后手动确认。' }

$en = Get-Process AMDRSServ -ErrorAction SilentlyContinue
if ($en) { Write-Host ('DVR 引擎已在运行 (PID ' + $en.Id + ')') }
else {
    Write-Host '启动 DVR 引擎（RSServCmd restart）...'
    [void](Start-EngineTask)
    for ($i = 0; $i -lt 40; $i++) { $en = Get-Process AMDRSServ -ErrorAction SilentlyContinue; if ($en) { break }; Start-Sleep -Seconds 1 }
    if (-not $en) {
        Write-Host '首次启动未见引擎，再试一次...'
        [void](Start-EngineTask)
        for ($i = 0; $i -lt 30; $i++) { $en = Get-Process AMDRSServ -ErrorAction SilentlyContinue; if ($en) { break }; Start-Sleep -Seconds 1 }
    }
}
$en = Get-Process AMDRSServ -ErrorAction SilentlyContinue
$ui = Get-Process RadeonSoftware -ErrorAction SilentlyContinue
$uiText = '未启动'
$enText = '未启动'
if ($ui) { $uiText = 'PID ' + $ui.Id }
if ($en) { $enText = 'PID ' + $en.Id }
Write-Host ('状态: 界面={0}  引擎={1}' -f $uiText, $enText)

param([ValidateSet('Toggle','On','Off')][string]$Action = 'Toggle')
# DVR 日志开关：HKCU\SOFTWARE\AMD\DVR\LOG
# 实测语义（2026-11-13，四代驱动一致）：
#   值存在（=1 或 =0）→ 引擎写 dvrlog；值整个缺失 → 完全不写。
#   所以「关」= 删除该值（写 0 并不能停写！）；「开」= 写入 1。
# 不带参数运行 = 切换；-Action On / -Action Off 可强制指定
$keyPath = 'HKCU:\SOFTWARE\AMD\DVR'
if (-not (Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
$curObj = Get-ItemProperty -Path $keyPath -Name LOG -ErrorAction SilentlyContinue
$exists = $null -ne $curObj
$curText = '未设置（不写日志）'
if ($exists) { $curText = ('{0}（写日志）' -f $curObj.LOG) }

if ($Action -eq 'On') { $wantOn = $true }
elseif ($Action -eq 'Off') { $wantOn = $false }
else { $wantOn = -not $exists }

if ($wantOn) {
    Set-ItemProperty -Path $keyPath -Name LOG -Value 1 -Type DWord
    $newText = '1（写日志）'
} else {
    Remove-ItemProperty -Path $keyPath -Name LOG -ErrorAction SilentlyContinue
    $newText = '已删除（不写日志）'
}
$chkObj = Get-ItemProperty -Path $keyPath -Name LOG -ErrorAction SilentlyContinue
$chkText = '未设置'
if ($null -ne $chkObj) { $chkText = "$($chkObj.LOG)" }

Write-Host '===== DVR 日志开关 =====' -ForegroundColor Cyan
Write-Host ('LOG: {0}  ->  {1}   （当前读回: {2}）' -f $curText, $newText, $chkText)
Write-Host '说明: 值存在（哪怕 =0）就会写 dvrlog，只有删除该值才停写；新值一般在下一次引擎启动后生效。'

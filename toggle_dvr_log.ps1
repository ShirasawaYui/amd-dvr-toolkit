param([ValidateSet('Toggle','On','Off')][string]$Action = 'Toggle')
# DVR 日志开关：HKCU\SOFTWARE\AMD\DVR\LOG  （1=开，0=关）
# 不带参数运行 = 切换；-Action On / -Action Off 可强制指定
$keyPath = 'HKCU:\SOFTWARE\AMD\DVR'
if (-not (Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
$cur = (Get-ItemProperty -Path $keyPath -Name LOG -ErrorAction SilentlyContinue).LOG
$curText = '未设置'
if ($null -ne $cur) { $curText = "$cur" }

$new = 0
if ($Action -eq 'On') { $new = 1 }
elseif ($Action -eq 'Off') { $new = 0 }
elseif ($cur -eq 1) { $new = 0 }
else { $new = 1 }

Set-ItemProperty -Path $keyPath -Name LOG -Value $new -Type DWord
$chk = (Get-ItemProperty -Path $keyPath -Name LOG).LOG

Write-Host '===== DVR 日志开关 =====' -ForegroundColor Cyan
Write-Host ('LOG: {0}  ->  {1}   （当前读回: {2}）' -f $curText, $new, $chk)
Write-Host '说明: 新值一般在“下一次引擎启动”后按新值执行；当前会话可能仍维持原状态。'

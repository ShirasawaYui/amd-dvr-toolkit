param(
    [ValidateSet('Toggle','On','Off','Status')][string]$Action = 'Toggle'
)
# DVR 日志开关（两代门控，2026-11-23 实测）
#
# 旧代（≤ 26.20.15.x）：HKCU\SOFTWARE\AMD\DVR 的 LOG **值**（DWORD）
#   实测（2026-11-13，四代一致）：值存在（=1 或 =0）→ 写 dvrlog；值整个缺失 → 停写。
#   所以旧代「关」必须删除该值，写 0 无效。
#
# 新代（≥ 26.20.29.02）：HKCU\SOFTWARE\AMD\DVR\LOG **子键** 的 log_enabled（DWORD）
#   实测（2026-11-23，两次受控重启，26.20.29.02）：
#     log_enabled=0 + 旧值 LOG=1（存在）→ 引擎不生成任何 dvrlog   → 0 就是关
#     log_enabled=1 + 旧值 LOG 缺失      → 引擎正常生成 dvrlog     → 旧值可完全废弃
#   即新代是标准布尔语义，与旧值无关。
#
# 注册表允许「同名值 + 同名子键」共存（见 HKCU\SOFTWARE\AMD\DVR 下同时存在
# LOG 值与 LOG 子键）。脚本对两处同时写入，对两代都得到正确结果：
#   开 = 子键 log_enabled 1 + 值 LOG 1
#   关 = 子键 log_enabled 0 + 值 LOG 删除
# 版本号只用于显示"当前按哪一代判据"与提示文案，不影响写入行为。

$keyOld = 'HKCU:\SOFTWARE\AMD\DVR'          # 旧代：值 LOG
$keyNew = 'HKCU:\SOFTWARE\AMD\DVR\LOG'      # 新代：子键 LOG\log_enabled
$engineExe = 'C:\Program Files\AMD\CNext\CNext\AMDRSServ.exe'

# ---------- 引擎版本 → 主判据 ----------
$isNew = $null
$verText = '未知'
if (Test-Path $engineExe) {
    $fvRaw = (Get-Item $engineExe).VersionInfo.FileVersion
    if ($fvRaw -match '(\d+)\.(\d+)\.(\d+)\.(\d+)') {
        $v = [version]('{0}.{1}.{2}.{3}' -f $matches[1], $matches[2], $matches[3], $matches[4])
        $verText = (($fvRaw -split ';')[0]).Trim()   # AMD 的 FileVersion 是复合串，取第一段（如 26.20.29.02）
        $isNew = ($v -ge [version]'26.20.29.0')
    }
}

# ---------- 读当前状态 ----------
$oldObj = Get-ItemProperty -Path $keyOld -Name LOG -ErrorAction SilentlyContinue
$oldExists = ($null -ne $oldObj)
$oldText = '未设置'
if ($oldExists) { $oldText = "$($oldObj.LOG)" }

$newVal = $null
if (Test-Path $keyNew) {
    $p = Get-ItemProperty -Path $keyNew -Name 'log_enabled' -ErrorAction SilentlyContinue
    if ($null -ne $p) { $newVal = [int]$p.log_enabled }
}
$newText = '未设置'
if ($null -ne $newVal) { $newText = "$newVal" }

if ($isNew -eq $true) { $effectiveOn = ($null -ne $newVal -and $newVal -ne 0) }
elseif ($isNew -eq $false) { $effectiveOn = $oldExists }
else { $effectiveOn = (($null -ne $newVal -and $newVal -ne 0) -or $oldExists) }

# ---------- 决定目标 ----------
switch ($Action) {
    'On'     { $wantOn = $true }
    'Off'    { $wantOn = $false }
    'Status' {
        Write-Host '===== DVR 日志开关（只读）=====' -ForegroundColor Cyan
        Write-Host ('引擎版本: {0}  →  按{1}判据' -f $verText, $(if ($isNew -eq $true) { '新代（子键 log_enabled）' } elseif ($isNew -eq $false) { '旧代（LOG 值）' } else { '两处并集' }))
        Write-Host ('旧代值 DVR\LOG        = {0}' -f $oldText)
        Write-Host ('新代值 DVR\LOG\log_enabled = {0}' -f $newText)
        Write-Host ('当前生效: {0}' -f $(if ($effectiveOn) { '写日志' } else { '不写日志' }))
        Write-Host '提示: 新值在下次引擎启动后生效。'
        return
    }
    default  { $wantOn = -not $effectiveOn }
}

# ---------- 写入（两处同时处理） ----------
if (-not (Test-Path $keyOld)) { New-Item -Path $keyOld -Force | Out-Null }
if (-not (Test-Path $keyNew)) { New-Item -Path $keyNew -Force | Out-Null }

if ($wantOn) {
    Set-ItemProperty -Path $keyNew -Name 'log_enabled' -Value 1 -Type DWord
    Set-ItemProperty -Path $keyOld -Name 'LOG' -Value 1 -Type DWord
    $newDesc = '开启'
} else {
    Set-ItemProperty -Path $keyNew -Name 'log_enabled' -Value 0 -Type DWord
    Remove-ItemProperty -Path $keyOld -Name 'LOG' -ErrorAction SilentlyContinue
    $newDesc = '关闭'
}

# ---------- 读回 ----------
$oldObj2 = Get-ItemProperty -Path $keyOld -Name LOG -ErrorAction SilentlyContinue
$oldRead = $(if ($null -ne $oldObj2) { "$($oldObj2.LOG)" } else { '已删除' })
$p2 = Get-ItemProperty -Path $keyNew -Name 'log_enabled' -ErrorAction SilentlyContinue
$newRead = $(if ($null -ne $p2) { "$($p2.log_enabled)" } else { '未设置' })

Write-Host '===== DVR 日志开关 =====' -ForegroundColor Cyan
Write-Host ('引擎版本: {0}（{1}）' -f $verText, $(if ($isNew -eq $true) { '新代' } elseif ($isNew -eq $false) { '旧代' } else { '版本未识别' }))
Write-Host ('目标: {0}' -f $newDesc) -ForegroundColor Green
Write-Host ('旧代 DVR\LOG       : {0}  ->  {1}' -f $oldText, $oldRead)
Write-Host ('新代 LOG\log_enabled: {0}  ->  {1}' -f $newText, $newRead)
Write-Host ''
Write-Host '两代语义差异（都已实测）:'
Write-Host '  · 旧代（≤26.20.15.x）：LOG 值存在（=1 或 =0 都算）就写日志，只有删除该值才停写。'
Write-Host '  · 新代（≥26.20.29.02）：LOG\log_enabled 1=写、0=停，与旧值无关。'
Write-Host '本脚本两处一起改，所以换驱动版本后不必再区分。'
Write-Host '新值在下次引擎启动后生效（重启引擎或重启电脑）。'

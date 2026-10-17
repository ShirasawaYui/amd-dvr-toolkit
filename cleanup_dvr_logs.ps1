param(
    [switch]$All,
    [switch]$DryRun
)
# AMD DVR 日志清理：%LOCALAPPDATA%\AMD\CN\dvrlog*.txt
# 保护规则：保留最新一份（当前会话）、保留最近 15 分钟写过的文件、
#           删除失败（被占用）自动跳过；默认不删“今天”的（加 -All 才删）
$dir = Join-Path $env:LOCALAPPDATA 'AMD\CN'
if (-not (Test-Path -LiteralPath $dir)) { Write-Host ("目录不存在：" + $dir); return }

$files = @(Get-ChildItem -LiteralPath $dir -Filter 'dvrlog*.txt' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
if ($files.Count -eq 0) { Write-Host '没有找到 dvrlog 文件。'; return }

$newest = $files[0]
$keepFrom = (Get-Date).AddMinutes(-15)
$today = (Get-Date).ToString('yyyyMMdd')
$deleted = New-Object System.Collections.Generic.List[string]
$skipped = New-Object System.Collections.Generic.List[string]
$freedMB = 0.0

foreach ($f in $files) {
    if ($f.FullName -eq $newest.FullName) { $skipped.Add('当前会话: ' + $f.Name); continue }
    if ($f.LastWriteTime -ge $keepFrom) { $skipped.Add('刚写入过: ' + $f.Name); continue }
    $m = [regex]::Match($f.Name, '^dvrlog(\d{8})-')
    $isToday = $m.Success -and ($m.Groups[1].Value -eq $today)
    if ($isToday -and (-not $All)) { $skipped.Add('今天的: ' + $f.Name); continue }
    if ($DryRun) { $deleted.Add(('(预览) {0}  {1:N1} MB' -f $f.Name, ($f.Length / 1MB))); continue }
    $sizeMB = $f.Length / 1MB
    try {
        Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
        $deleted.Add(('{0}  {1:N1} MB' -f $f.Name, $sizeMB))
        $freedMB = $freedMB + $sizeMB
    }
    catch {
        $skipped.Add('被占用,跳过: ' + $f.Name)
    }
}

Write-Host '===== DVR 日志清理 =====' -ForegroundColor Cyan
if ($DryRun) { Write-Host ("扫描到 {0} 份日志（预览模式，不删除）" -f $files.Count) }
else { Write-Host ("扫描到 {0} 份日志，已删除 {1} 份" -f $files.Count, $deleted.Count) }
foreach ($x in $deleted) { Write-Host ('  - ' + $x) }
if ($skipped.Count -gt 0) {
    Write-Host ('保留 {0} 份：' -f $skipped.Count)
    foreach ($x in $skipped) { Write-Host ('  . ' + $x) }
}
if (-not $DryRun) { Write-Host ("本次释放约 {0:N1} MB" -f $freedMB) -ForegroundColor Green }

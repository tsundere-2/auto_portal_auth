# 先记录基线
$before = Get-Date -Format 'HH:mm:ss'
Write-Output "BEFORE=$before"
# 触发睡眠 8 秒后自动唤醒（若固件支持 RTC 唤醒）
rundll32.exe powrprof.dll,SetSuspendState 0,1,0

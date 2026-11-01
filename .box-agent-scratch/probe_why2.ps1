$ErrorActionPreference = 'SilentlyContinue'

Write-Output "=== A. 睡眠前(00:19-00:21) 与 唤醒后(12:07-12:10) 的应用日志全貌 ==="
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime='2026-11-01 00:18:00'; EndTime='2026-11-01 12:12:00'} -MaxEvents 50 |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, ProviderName, @{n='M'; e={ ($_.Message -split "`r?`n")[0] }} |
    Format-Table -AutoSize -Wrap

Write-Output "`n=== B. 是否有 Application Hang / 进程被结束 的记录 ==="
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime='2026-11-01 00:00:00'; Id=1000,1001,1002} -MaxEvents 20 |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, @{n='M'; e={ ($_.Message -split "`r?`n")[0..2] -join ' | ' }} |
    Format-Table -AutoSize -Wrap

Write-Output "`n=== C. 系统日志：休眠期间是否发生过 'Power-Troubleshooter 唤醒源' ==="
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Power-Troubleshooter'; StartTime='2026-11-01 00:00:00'} -MaxEvents 10 |
    Select-Object TimeCreated, Id, @{n='M'; e={ ($_.Message -split "`r?`n")[0] }} |
    Format-Table -AutoSize -Wrap

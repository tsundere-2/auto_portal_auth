$ErrorActionPreference = 'SilentlyContinue'

Write-Output "=== 1. 电源事件（Kernel-Power 42=进睡眠/107=恢复/109=内核关机/131=唤醒源）==="
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; ID=42,107,109,131} -MaxEvents 15 |
    Select-Object TimeCreated, Id, @{n='Msg'; e={ ($_.Message -split "`r?`n")[0] }} |
    Format-Table -AutoSize -Wrap

Write-Output "`n=== 2. 昨晚 20:00 后的应用错误/挂起（python 相关）==="
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime='2026-10-29 20:00:00'; Level=1,2,3} -MaxEvents 60 |
    Where-Object { $_.Message -match 'python' } |
    Select-Object TimeCreated, Id, ProviderName, @{n='Msg'; e={ ($_.Message -split "`r?`n")[0..2] -join ' / ' }} |
    Format-Table -AutoSize -Wrap

Write-Output "`n=== 3. 系统日志 21:00 之后的开关机/休眠记录 ==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime='2026-10-29 21:00:00'; ID=1,12,13,41,1074,6005,6006,6008} -MaxEvents 20 |
    Select-Object TimeCreated, Id, ProviderName, @{n='Msg'; e={ ($_.Message -split "`r?`n")[0] }} |
    Format-Table -AutoSize -Wrap

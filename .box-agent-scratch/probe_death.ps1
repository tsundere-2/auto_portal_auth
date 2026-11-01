$ErrorActionPreference = 'SilentlyContinue'

Write-Output "=== A. 00:20:08 之后到 12:08 之间是否有睡眠/关机事件 ==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime='2026-11-01 00:20:00'; EndTime='2026-11-01 12:10:00'; ID=42,107,109,1,12,13,41,1074,6005,6006,6008,6013} -MaxEvents 40 |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, ProviderName, @{n='M'; e={ ($_.Message -split "`r?`n")[0] }} |
    Format-Table -AutoSize -Wrap

Write-Output "`n=== B. 11-01 00:20~00:30 应用日志（找 python 被杀/崩溃）==="
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime='2026-11-01 00:18:00'; EndTime='2026-11-01 00:40:00'} -MaxEvents 40 |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, ProviderName, @{n='M'; e={ ($_.Message -split "`r?`n")[0] }} |
    Format-Table -AutoSize -Wrap

Write-Output "`n=== C. 睡眠相关：是否有'应用因电源状态被关闭'记录 ==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime='2026-11-01 00:15:00'; EndTime='2026-11-01 00:35:00'} -MaxEvents 60 |
    Where-Object { $_.ProviderName -match 'Power|Kernel-Power|Application-Experience|Winlogon|User Profile' } |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, ProviderName, @{n='M'; e={ ($_.Message -split "`r?`n")[0] }} |
    Format-Table -AutoSize -Wrap

Write-Output "`n=== D. 是否装了会杀后台的厂商电源管理 ==="
Get-CimInstance Win32_Product -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'Lenovo|ASUS|Dell|HP|Power|Battery|Manager|管家' } |
    Select-Object Name -First 10 | Format-Table -AutoSize

Write-Output "`n=== E. 当前电源计划的'允许混合睡眠/休眠' ==="
powercfg /a 2>&1 | Select-Object -First 12

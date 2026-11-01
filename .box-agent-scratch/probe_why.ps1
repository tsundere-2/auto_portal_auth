$ErrorActionPreference = 'SilentlyContinue'

Write-Output "=== A. 11-01 00:15~00:25 睡眠前后事件 ==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime='2026-11-01 00:15:00'; EndTime='2026-11-01 00:25:00'} -MaxEvents 40 |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, ProviderName, @{n='M'; e={ ($_.Message -split "`r?`n")[0] }} |
    Format-Table -AutoSize -Wrap

Write-Output "`n=== B. 11-01 12:05~12:20 唤醒前后事件 ==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime='2026-11-01 12:05:00'; EndTime='2026-11-01 12:20:00'} -MaxEvents 40 |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, ProviderName, @{n='M'; e={ ($_.Message -split "`r?`n")[0] }} |
    Format-Table -AutoSize -Wrap

Write-Output "`n=== C. 计划任务是否存在 ==="
schtasks /Query /TN "AutoPortalAuthWatchdog" 2>&1 | Select-Object -First 3

Write-Output "`n=== D. 自启项 ==="
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' |
    Select-Object AutoPortalAuth, AutoPortalAuthWatchdog | Format-List

Write-Output "`n=== E. 心跳文件 ==="
Get-ChildItem D:\auto_portal_auth\data -Filter '*.json' | Select-Object Name, LastWriteTime, Length | Format-Table -AutoSize

$ErrorActionPreference = 'SilentlyContinue'

Write-Output "=== 23:50 ~ 次日 00:10 全部系统事件（找进程退出/关机/崩溃）==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime='2026-10-29 23:45:00'; EndTime='2026-10-30 00:20:00'} -MaxEvents 60 |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, ProviderName, @{n='Msg'; e={ (($_.Message -split "`r?`n")[0]) }} |
    Format-Table -AutoSize -Wrap

Write-Output "`n=== 21:00 ~ 23:59 事件 42/107/109/41/1074/6008 ==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime='2026-10-29 21:00:00'; ID=42,107,109,41,1074,6008,6013} -MaxEvents 30 |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, ProviderName, @{n='Msg'; e={ ($_.Message -split "`r?`n")[0] }} |
    Format-Table -AutoSize -Wrap

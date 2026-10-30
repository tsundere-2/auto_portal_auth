$ErrorActionPreference = 'SilentlyContinue'

Write-Output "=== A. 21:00~21:10 系统事件 ==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime='2026-10-29 20:58:00'; EndTime='2026-10-29 21:15:00'} -MaxEvents 40 |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, ProviderName, @{n='Msg'; e={ ($_.Message -split "`r?`n")[0] }} |
    Format-Table -AutoSize -Wrap

Write-Output "`n=== B. 21:00~21:10 应用日志全部 ==="
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime='2026-10-29 20:55:00'; EndTime='2026-10-29 21:20:00'} -MaxEvents 40 |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, ProviderName, @{n='Msg'; e={ ($_.Message -split "`r?`n")[0] }} |
    Format-Table -AutoSize -Wrap

Write-Output "`n=== C. 当前 pythonw 进程与命令行 ==="
Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" |
    Select-Object ProcessId, Name, CommandLine | Format-List

Write-Output "`n=== D. 会话状态（是否锁屏/远程）==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime='2026-10-29 20:55:00'; EndTime='2026-10-29 21:10:00'; ID=7001,7002,7003} -MaxEvents 10 |
    Select-Object TimeCreated, Id, ProviderName | Format-Table -AutoSize

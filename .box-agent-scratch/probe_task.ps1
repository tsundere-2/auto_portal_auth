$ErrorActionPreference = 'SilentlyContinue'
Write-Output "=== TaskScheduler 操作日志（近 15 分钟）==="
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; StartTime=(Get-Date).AddMinutes(-15)} -MaxEvents 25 |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, @{n='Msg'; e={ ($_.Message -split "`r?`n")[0] }} |
    Format-Table -AutoSize -Wrap

Write-Output "`n=== 任务配置：执行动作与 Job 相关设置 ==="
$t = Get-ScheduledTask -TaskName 'AutoPortalAuthWatchdog'
$t.Actions | Format-List Execute, Arguments, WorkingDirectory
$t.Settings | Select-Object ExecutionTimeLimit, AllowHardTerminate, MultipleInstances, DisallowStartIfOnBatteries, StopIfGoingOnBatteries | Format-List

Write-Output "`n=== 当前 python 进程 ==="
Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" |
    Select-Object ProcessId, Name, CommandLine | Format-List

$ErrorActionPreference = 'SilentlyContinue'

Write-Output "=== A. WER 1001 详情（21:06:21）==="
Get-WinEvent -FilterHashtable @{LogName='Application'; ID=1001; StartTime='2026-10-29 20:00:00'; EndTime='2026-10-30 13:00:00'} -MaxEvents 10 |
    Select-Object TimeCreated, @{n='Msg'; e={ $_.Message }} |
    Format-List

Write-Output "`n=== B. WER 报告目录下 python 相关 ==="
Get-ChildItem -Path "$env:LOCALAPPDATA\CrashDumps","$env:ProgramData\Microsoft\Windows\WER\ReportArchive","$env:ProgramData\Microsoft\Windows\WER\ReportQueue" -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'python' } |
    Select-Object LastWriteTime, Length, FullName | Format-Table -AutoSize -Wrap

Write-Output "`n=== C. 21:00~21:15 网卡事件（mtkwecx = 无线网卡驱动）==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime='2026-10-29 20:40:00'; EndTime='2026-10-29 21:30:00'} -MaxEvents 60 |
    Where-Object { $_.ProviderName -match 'mtkwecx|Tcpip|Dhcp|NDIS|netwtw|e1i|Rtk' } |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, ProviderName, @{n='Msg'; e={ (($_.Message -split "`r?`n")[0]).Substring(0,[Math]::Min(90,(($_.Message -split "`r?`n")[0]).Length)) }} |
    Format-Table -AutoSize -Wrap

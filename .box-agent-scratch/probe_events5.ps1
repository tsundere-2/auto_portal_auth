$ErrorActionPreference = 'SilentlyContinue'

Write-Output "=== A. 网卡/链路：21:00 之后 DHCP 与链路事件 ==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime='2026-10-29 20:50:00'} -MaxEvents 200 |
    Where-Object { $_.ProviderName -match 'Dhcp|Tcpip|NDIS|mtkwecx|netwtw|e1i|Netwtw|Rtl|Realtek' -and $_.Id -in 1003,1004,1006,1007,12,13,4201,4202,7001,7002,1030,1035,1036,50037 } |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, ProviderName, @{n='Msg'; e={ (($_.Message -split "`r?`n")[0]) }} |
    Format-Table -AutoSize -Wrap

Write-Output "`n=== B. 今天 12:18 唤醒后到现在的网络事件 ==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime='2026-10-30 12:15:00'} -MaxEvents 150 |
    Where-Object { $_.ProviderName -match 'Dhcp|Tcpip|NDIS|mtkwecx|Netwtw|e1i|Realtek' } |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, ProviderName, @{n='Msg'; e={ (($_.Message -split "`r?`n")[0]) }} |
    Format-Table -AutoSize -Wrap

Write-Output "`n=== C. 当前网络接口与 IP ==="
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' } |
    Select-Object InterfaceAlias, IPAddress, PrefixLength, AddressState |
    Format-Table -AutoSize

Write-Output "`n=== D. 开机自启注册表项 ==="
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Format-List

$ErrorActionPreference = 'SilentlyContinue'

Write-Output "=== A. 10-30 15:00 之后电源事件 ==="
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; ID=42,107,109,131,187} -MaxEvents 25 |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, @{n='Msg'; e={ ($_.Message -split "`r?`n")[0] }} |
    Format-Table -AutoSize -Wrap

Write-Output "`n=== B. 唤醒后到现在的网络/链路事件 ==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime='2026-10-30 15:00:00'} -MaxEvents 300 |
    Where-Object { $_.ProviderName -match 'Dhcp|Tcpip|NDIS|mtkwecx|Netwtw|e1i|Realtek|Kernel-Power' -and $_.Id -in 42,107,131,1003,1004,1006,1007,4201,4202,50037,1030,1035,1036 } |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, ProviderName, @{n='Msg'; e={ (($_.Message -split "`r?`n")[0]) }} |
    Format-Table -AutoSize -Wrap

Write-Output "`n=== C. 当前是否真的能上网 ==="
try {
    $r = Invoke-WebRequest -Uri 'http://www.msftconnecttest.com/connecttest.txt' -TimeoutSec 8 -UseBasicParsing
    Write-Output ("msft: HTTP {0}  body={1}" -f $r.StatusCode, $r.Content.Trim())
} catch {
    Write-Output ("msft 失败: {0}" -f $_.Exception.Message)
}
Write-Output "`n=== D. 当前 IPv4 与网关 ==="
Get-NetIPConfiguration | Where-Object { $_.IPv4Address -and $_.NetAdapter.Status -eq 'Up' } |
    Select-Object InterfaceAlias, @{n='IP';e={$_.IPv4Address.IPAddress}}, @{n='GW';e={$_.IPv4DefaultGateway.NextHop}} |
    Format-Table -AutoSize

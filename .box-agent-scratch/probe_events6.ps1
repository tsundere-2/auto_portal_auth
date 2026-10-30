$ErrorActionPreference = 'SilentlyContinue'

Write-Output "=== A. 唤醒前后（12:15~12:25）全部系统事件 ==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime='2026-10-30 12:15:00'; EndTime='2026-10-30 12:30:00'} -MaxEvents 80 |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, ProviderName, @{n='Msg'; e={ (($_.Message -split "`r?`n")[0]) }} |
    Format-Table -AutoSize -Wrap

Write-Output "`n=== B. 以太网（59.79.4.243 所在）改过路由/网关时间 ==="
Get-NetIPInterface -AddressFamily IPv4 | Select-Object InterfaceAlias, InterfaceIndex, ConnectionState, Dhcp | Format-Table -AutoSize

Write-Output "`n=== C. 今天 Edge 启动记录 & 访问的域名（可能留下 portal 痕迹）==="
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Edge'; StartTime='2026-10-30 12:00:00'} -MaxEvents 10 |
    Select-Object TimeCreated, @{n='Msg'; e={ ($_.Message -split "`r?`n")[0] }} | Format-Table -AutoSize -Wrap

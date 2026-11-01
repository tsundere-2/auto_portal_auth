$ErrorActionPreference = 'Stop'
$log = 'D:\auto_portal_auth\.box-agent-scratch\task_test.txt'
Remove-Item $log -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c echo ran > "D:\auto_portal_auth\.box-agent-scratch\task_test.txt"' -WorkingDirectory 'D:\auto_portal_auth'
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(1)

Register-ScheduledTask -TaskName 'APATestMinimal' -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName 'APATestMinimal'
Start-Sleep -Seconds 6

$info = Get-ScheduledTaskInfo -TaskName 'APATestMinimal'
Write-Output ("LastTaskResult = {0}  (0x{0:X})" -f $info.LastTaskResult)
Write-Output ("State          = {0}" -f (Get-ScheduledTask -TaskName 'APATestMinimal').State)
Write-Output ("文件是否生成   = {0}" -f (Test-Path $log))
if (Test-Path $log) { Write-Output ("内容: " + (Get-Content $log)) }

Unregister-ScheduledTask -TaskName 'APATestMinimal' -Confirm:$false

$ErrorActionPreference = 'Stop'
$root = 'D:\auto_portal_auth'
$py = 'C:\Users\14976\AppData\Local\Programs\Python\Python312\pythonw.exe'

Write-Output "=== Register watchdog scheduled task ==="

$action = New-ScheduledTaskAction -Execute $py -Argument "-X utf8 `"$root\auto_portal_auth.py`" watchdog" -WorkingDirectory $root

$t_logon = New-ScheduledTaskTrigger -AtLogOn
$t_logon.Delay = 'PT20S'
$t_time = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes 5)

$q = "*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=107 or EventID=131)]]"
$class = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
$t_wake = New-CimInstance -CimClass $class -ClientOnly
$t_wake.Enabled = $true
$t_wake.Subscription = "<QueryList><Query Id='0' Path='System'><Select Path='System'>" + $q + "</Select></Query></QueryList>"
$t_wake.Delay = 'PT3S'

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName 'AutoPortalAuthWatchdog' -Action $action -Trigger @($t_logon,$t_time,$t_wake) -Settings $settings -Principal $principal -Force | Out-Null
Write-Output "registered"

Start-ScheduledTask -TaskName 'AutoPortalAuthWatchdog'
Start-Sleep -Seconds 12
$info = Get-ScheduledTaskInfo -TaskName 'AutoPortalAuthWatchdog'
Write-Output ("LastTaskResult = " + $info.LastTaskResult + " (0x" + ('{0:X}' -f $info.LastTaskResult) + ")")
Write-Output ("State = " + (Get-ScheduledTask -TaskName 'AutoPortalAuthWatchdog').State)

$trg = Get-ScheduledTask -TaskName 'AutoPortalAuthWatchdog'
foreach ($t in $trg.Triggers) { Write-Output ("  trigger: " + $t.CimClass.CimClassName) }

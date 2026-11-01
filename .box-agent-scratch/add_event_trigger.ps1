$ErrorActionPreference = 'Stop'

# 读取已注册任务，追加 EventTrigger（系统唤醒），保留原有触发器和设置
$task = Get-ScheduledTask -TaskName 'AutoPortalAuthWatchdog'
Write-Output ("current triggers: " + $task.Triggers.Count)

$q = "*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=107 or EventID=131)]]"
$sub = "<QueryList><Query Id='0' Path='System'><Select Path='System'>" + $q + "</Select></Query></QueryList>"

# 直接用 XML 方式替换：CIM 构造的 EventTrigger 在注册时容易丢
$x = Export-ScheduledTask -TaskName 'AutoPortalAuthWatchdog'
$evtXml = @"
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>$sub</Subscription>
      <Delay>PT3S</Delay>
    </EventTrigger>
"@
if ($x -match '</Triggers>') {
    $x = $x -replace '</Triggers>', ($evtXml + '  </Triggers>')
} else {
    throw 'Triggers element not found in task XML'
}
$x | Out-File -FilePath 'D:\auto_portal_auth\.box-agent-scratch\task_final.xml' -Encoding Unicode
Register-ScheduledTask -TaskName 'AutoPortalAuthWatchdog' -Xml $x -Force | Out-Null
Write-Output "re-registered with EventTrigger"

Start-ScheduledTask -TaskName 'AutoPortalAuthWatchdog'
Start-Sleep -Seconds 12
$i = Get-ScheduledTaskInfo -TaskName 'AutoPortalAuthWatchdog'
Write-Output ("LastTaskResult = " + $i.LastTaskResult)
Write-Output ("State = " + (Get-ScheduledTask -TaskName 'AutoPortalAuthWatchdog').State)
$t2 = Get-ScheduledTask -TaskName 'AutoPortalAuthWatchdog'
foreach ($t in $t2.Triggers) { Write-Output ("  trigger: " + $t.CimClass.CimClassName) }

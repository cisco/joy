Param(
[switch] $Start,
[switch] $Unregister
)

if($Unregister) {
    # Remove the scheduled task, and then exit script
    Unregister-ScheduledTask -TaskName "JoyTask" -Confirm:$false
    break
}

# 32 or 64 bit?
if ([System.IntPtr]::Size -eq 4) {
    $progfiles = ${env:ProgramFiles(x86)}
} else {
    $progfiles = $env:ProgramFiles
}

$username = $env:USERNAME

$action = New-ScheduledTaskAction -Execute "$progfiles\Joy\win-joy.exe" -Argument "-x win-options.cfg"

$trigger = New-ScheduledTaskTrigger -AtLogOn -User $username

$principal = New-ScheduledTaskPrincipal -UserId $username -LogonType Interactive

Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName "JoyTask" -Description "Advanced flow monitoring"

if($Start) {
    Start-ScheduledTask -TaskName "JoyTask"
}

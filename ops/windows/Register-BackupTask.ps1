# Registers the TalkXNightlyBackup scheduled task (daily 04:00 local, SYSTEM).
# Requires an elevated PowerShell. Idempotent: re-running copies the scripts again
# and re-registers the task with the same definition.
[CmdletBinding()]
param(
    [string]$TalkXRoot = 'C:\TalkX',
    [string]$At = '04:00'
)
$ErrorActionPreference = 'Stop'
$target = Join-Path $TalkXRoot 'ops\windows'
New-Item -ItemType Directory -Path $target -Force | Out-Null
foreach ($name in @('Backup.ps1', 'backup.cjs')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $target $name) -Force
}
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}\Backup.ps1"' -f $target) `
    -WorkingDirectory $TalkXRoot
$trigger = New-ScheduledTaskTrigger -Daily -At $At
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew
if (Get-ScheduledTask -TaskName 'TalkXNightlyBackup' -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName 'TalkXNightlyBackup' -Confirm:$false
}
Register-ScheduledTask -TaskName 'TalkXNightlyBackup' -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Description 'TalkX nightly encrypted database backup (pg_dump + AES-256-GCM, 14 day retention).' | Out-Null
Get-ScheduledTask -TaskName 'TalkXNightlyBackup' | Select-Object TaskName, State
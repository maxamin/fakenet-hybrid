# Installs a FakeNet hybrid package (unpacked; run from its top directory, as
# Administrator) to C:\FakeNetHybrid, with two scheduled tasks that start at boot as SYSTEM.
# Inside the analysis VM only. It never enables diversion: review the config and set
# [diverter] enabled = true yourself. Needs Java 21 on PATH.
$ErrorActionPreference = 'Stop'
$Root = 'C:\FakeNetHybrid'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run as Administrator'
}
$Java = (Get-Command java.exe).Source

New-Item -ItemType Directory -Force -Path "$Root\bin", "$Root\daemon", "$Root\capture", "$Root\audit" | Out-Null
Copy-Item bin\fakenet-nucleus.exe, bin\WinDivert.dll, bin\WinDivert64.sys "$Root\bin\" -Force
Copy-Item daemon\fakenet-daemon.jar "$Root\daemon\" -Force
Copy-Item daemon\lib, daemon\routes "$Root\daemon\" -Recurse -Force
Copy-Item config\default-files $Root -Recurse -Force

$Config = "$Root\fakenet.toml"
if (-not (Test-Path $Config)) {
    (Get-Content config\fakenet.toml) `
        -replace '^capture_dir = .*', "capture_dir = 'C:\FakeNetHybrid\capture'" `
        -replace '^# *secret_file = .*', "secret_file = 'C:\FakeNetHybrid\link.secret'" `
        -replace '"default-files"', "'C:\FakeNetHybrid\default-files'" | Set-Content $Config
}
$Secret = "$Root\link.secret"
if (-not (Test-Path $Secret)) {
    & "$Root\bin\fakenet-nucleus.exe" --generate-secret $Secret
    # Only SYSTEM and Administrators may read the link secret
    icacls $Secret /inheritance:r /grant:r 'SYSTEM:R' 'Administrators:R' | Out-Null
}

$Startup = New-ScheduledTaskTrigger -AtStartup
$System = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
$Daemon = New-ScheduledTaskAction -Execute $Java -WorkingDirectory "$Root\daemon" `
    -Argument "-Dfakenet.link.secret-file=$Secret -Dfakenet.audit.dir=$Root\audit -jar $Root\daemon\fakenet-daemon.jar"
$Nucleus = New-ScheduledTaskAction -Execute "$Root\bin\fakenet-nucleus.exe" -WorkingDirectory $Root -Argument "-c $Config"
Register-ScheduledTask -TaskName 'FakeNet hybrid daemon' -Action $Daemon -Trigger $Startup -Principal $System -Settings $Settings -Force | Out-Null
Register-ScheduledTask -TaskName 'FakeNet hybrid nucleus' -Action $Nucleus -Trigger $Startup -Principal $System -Settings $Settings -Force | Out-Null
Write-Host "Installed. Review $Config, then: Start-ScheduledTask 'FakeNet hybrid daemon'; Start-ScheduledTask 'FakeNet hybrid nucleus'"

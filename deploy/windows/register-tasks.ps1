# Registers the FakeNet hybrid scheduled tasks for an already-installed payload (the tar.gz
# install.ps1 and the MSI both call this). $Root is the install folder holding bin\, daemon\
# and config\; runtime data (capture, audit, the link secret and the live config) goes under
# C:\ProgramData\FakeNetHybrid, which services can write and Program Files can't. Run as
# Administrator, inside the analysis VM. Never enables diversion. Needs Java 21 on PATH.
param([string]$Root = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run as Administrator'
}
$Java = (Get-Command java.exe).Source
$Nucleus = Join-Path $Root 'bin\fakenet-nucleus.exe'
if (-not (Test-Path $Nucleus)) { throw "fakenet-nucleus.exe not found under $Root\bin" }

$Data = 'C:\ProgramData\FakeNetHybrid'
New-Item -ItemType Directory -Force -Path "$Data\capture", "$Data\audit" | Out-Null

$Config = "$Data\fakenet.toml"
if (-not (Test-Path $Config)) {
    (Get-Content (Join-Path $Root 'config\fakenet.toml')) `
        -replace '^capture_dir = .*', "capture_dir = '$Data\capture'" `
        -replace '^# *secret_file = .*', "secret_file = '$Data\link.secret'" `
        -replace '"default-files"', "'$Root\config\default-files'" | Set-Content $Config
}
$Secret = "$Data\link.secret"
if (-not (Test-Path $Secret)) {
    & $Nucleus --generate-secret $Secret
    icacls $Secret /inheritance:r /grant:r 'SYSTEM:R' 'Administrators:R' | Out-Null
}

$Startup = New-ScheduledTaskTrigger -AtStartup
$System = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
$Daemon = New-ScheduledTaskAction -Execute $Java -WorkingDirectory "$Root\daemon" `
    -Argument "-Dfakenet.link.secret-file=$Secret -Dfakenet.audit.dir=$Data\audit -jar $Root\daemon\fakenet-daemon.jar"
$NucleusAction = New-ScheduledTaskAction -Execute $Nucleus -WorkingDirectory $Root -Argument "-c $Config"
Register-ScheduledTask -TaskName 'FakeNet hybrid daemon' -Action $Daemon -Trigger $Startup -Principal $System -Settings $Settings -Force | Out-Null
Register-ScheduledTask -TaskName 'FakeNet hybrid nucleus' -Action $NucleusAction -Trigger $Startup -Principal $System -Settings $Settings -Force | Out-Null
Write-Host "Registered. Review $Config, then: Start-ScheduledTask 'FakeNet hybrid daemon'; Start-ScheduledTask 'FakeNet hybrid nucleus'"

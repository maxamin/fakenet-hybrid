# Installs a FakeNet hybrid package (unpacked; run from its top directory, as
# Administrator) to C:\FakeNetHybrid, then registers two scheduled tasks that start at boot
# as SYSTEM (via register-tasks.ps1, shared with the MSI). Runtime data goes under
# C:\ProgramData\FakeNetHybrid. Inside the analysis VM only. It never enables diversion:
# review the config and set [diverter] enabled = true yourself. Needs Java 21 on PATH.
$ErrorActionPreference = 'Stop'
$Root = 'C:\FakeNetHybrid'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run as Administrator'
}

New-Item -ItemType Directory -Force -Path "$Root\bin", "$Root\daemon", "$Root\config" | Out-Null
Copy-Item bin\fakenet-nucleus.exe, bin\WinDivert.dll, bin\WinDivert64.sys "$Root\bin\" -Force
Copy-Item daemon\fakenet-daemon.jar "$Root\daemon\" -Force
Copy-Item daemon\lib, daemon\routes "$Root\daemon\" -Recurse -Force
Copy-Item config\fakenet.toml, config\default-files, config\fingerprints, config\hooks "$Root\config\" -Recurse -Force
Copy-Item deploy\windows\register-tasks.ps1, deploy\windows\uninstall.ps1 "$Root\" -Force

& "$Root\register-tasks.ps1" -Root $Root

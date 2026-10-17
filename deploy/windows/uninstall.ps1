# Stops and removes the FakeNet hybrid scheduled tasks (captures in C:\ProgramData\FakeNetHybrid are kept:
# they hold the captures). Run as Administrator.
$ErrorActionPreference = 'Continue'
foreach ($Task in 'FakeNet hybrid nucleus', 'FakeNet hybrid daemon') {
    Stop-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue
}
Write-Host 'Removed the scheduled tasks. Captures remain in C:\ProgramData\FakeNetHybrid\capture.'

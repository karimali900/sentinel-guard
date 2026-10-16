# Windows auto-install (PowerShell, Run as Administrator)
# Sets up SentinelGuard to run 24/7 at logon with popup alerts, no manual steps.
$ErrorActionPreference = "Stop"
$SrcDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Dest = "C:\SentinelGuard"

Write-Host "[1/4] Installing Python dependency..."
pip install -r "$SrcDir\requirements.txt"

Write-Host "[2/4] Copying files to $Dest..."
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item "$SrcDir\sentinel.py" "$Dest\" -Force
Copy-Item "$SrcDir\sentinel_report.py" "$Dest\" -Force
Copy-Item "$SrcDir\config.json" "$Dest\" -Force

Write-Host "[3/4] Ensuring Windows Firewall is ON..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

Write-Host "[4/4] Creating Scheduled Task for autostart (at logon + at startup)..."
$Python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $Python) { $Python = (Get-Command python3 -ErrorAction SilentlyContinue).Source }
if (-not $Python) { throw "Python not found in PATH. Install Python 3 from python.org and tick 'Add to PATH'." }

$Action = New-ScheduledTaskAction -Execute $Python -Argument "`"$Dest\sentinel.py`""
$Trigger1 = New-ScheduledTaskTrigger -AtLogOn
$Trigger2 = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -RunLevel Highest -LogonType Interactive
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName "SentinelGuard" -Action $Action -Trigger @($Trigger1,$Trigger2) -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName "SentinelGuard"

Write-Host ""
Write-Host "Done. SentinelGuard is RUNNING and will auto-start on every boot/logon."
Write-Host "Check: Get-ScheduledTask -TaskName SentinelGuard"
Write-Host "Logs:  $Dest\sentinel.log"

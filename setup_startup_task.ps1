# PowerShell script to register AICyberAuditBox as a startup task on Windows logon
# This ensures that when you boot the VM and log in (via RDP), the application starts automatically.

$projectDir = $PSScriptRoot
if (-not $projectDir) { 
    $projectDir = $pwd.Path 
}

$batPath = Join-Path $projectDir "run_llamacpp_demo.bat"

# Verify the batch file exists
if (-not (Test-Path $batPath)) {
    Write-Error "Could not find run_llamacpp_demo.bat in $projectDir. Please run this script from the project folder."
    exit 1
}

Write-Host "Registering scheduled task to run $batPath at logon..." -ForegroundColor Cyan

# Define task action (run the batch file from its directory)
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$batPath`"" -WorkingDirectory $projectDir

# Define task trigger (runs when the user logs in, which is required for Docker Desktop)
$trigger = New-ScheduledTaskTrigger -AtLogon

# Define task settings (allow running on battery, don't stop task, etc.)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 365)

# Register the scheduled task with Admin privileges
try {
    Register-ScheduledTask -TaskName "AICyberAuditBox_Startup" -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force
    Write-Host "`n[SUCCESS] Startup task registered successfully!" -ForegroundColor Green
    Write-Host "The application will launch automatically every time you log on to this VM." -ForegroundColor Green
} catch {
    Write-Error "Failed to register scheduled task. Please make sure you are running PowerShell as Administrator."
}

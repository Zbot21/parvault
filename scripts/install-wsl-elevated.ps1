# Run this script in Windows to trigger the UAC Administrator prompt for WSL2 Ubuntu installation
Start-Process powershell -Verb RunAs -ArgumentList "-NoExit", "-Command", "Write-Host '=== Installing WSL2 + Ubuntu for Project ParVault ===' -ForegroundColor Cyan; wsl --install -d Ubuntu"

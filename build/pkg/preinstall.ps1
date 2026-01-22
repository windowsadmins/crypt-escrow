# Crypt preinstall script
# Version: {{VERSION}}

Write-Host "Crypt {{VERSION}} - Pre-installation checks" -ForegroundColor Cyan

# Check for BitLocker support
try {
    $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
    if ($tpm) {
        Write-Host "TPM detected: Ready for BitLocker key escrow" -ForegroundColor Green
    } else {
        Write-Host "No TPM detected - BitLocker may use password-only mode" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Could not check TPM status" -ForegroundColor Yellow
}

# Stop any existing scheduled tasks
try {
    $task = Get-ScheduledTask -TaskName "Crypt*" -ErrorAction SilentlyContinue
    if ($task) {
        Write-Host "Stopping existing Crypt scheduled task..." -ForegroundColor Cyan
        $task | Stop-ScheduledTask -ErrorAction SilentlyContinue
        $task | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
    }
} catch {
    # Ignore errors
}

Write-Host "Pre-installation checks complete" -ForegroundColor Green

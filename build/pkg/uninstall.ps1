# Crypt uninstall script
# Version: {{VERSION}}

# Close the app, then remove the all-users Start Menu shortcut the postinstall created.
Get-Process -Name 'Managed Encryption Escrow' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue

$shortcutPath = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Managed Encryption Escrow.lnk'
if (Test-Path -LiteralPath $shortcutPath) {
    Remove-Item -LiteralPath $shortcutPath -Force
    Write-Host "Removed $shortcutPath" -ForegroundColor Green
}

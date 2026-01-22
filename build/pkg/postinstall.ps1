# Crypt postinstall script
# Version: {{VERSION}}

$installPath = 'C:\Program Files\Crypt'
$configDir = 'C:\ProgramData\ManagedEncryption'
$configFile = Join-Path $configDir 'config.yaml'

Write-Host "Crypt {{VERSION}} - Post-installation" -ForegroundColor Cyan

# Add to system PATH
$currentPath = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
if ($currentPath -notlike "*$installPath*") {
    $newPath = "$currentPath;$installPath"
    [Environment]::SetEnvironmentVariable('PATH', $newPath, 'Machine')
    Write-Host "Added $installPath to system PATH" -ForegroundColor Green
} else {
    Write-Host "PATH already configured" -ForegroundColor Cyan
}

# Create config directory
if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    Write-Host "Created config directory: $configDir" -ForegroundColor Green
}

# Create logs directory
$logsDir = Join-Path $configDir 'logs'
if (-not (Test-Path $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
}

# Configure from environment variable if set
$serverUrl = [Environment]::GetEnvironmentVariable('CRYPT_ESCROW_SERVER_URL', 'Machine')
if ($serverUrl -and -not (Test-Path $configFile)) {
    Write-Host "Configuring Crypt server: $serverUrl" -ForegroundColor Cyan
    $config = @"
server:
  url: $serverUrl
  skip_cert_check: false

escrow:
  auto_rotate: true
  cleanup_old_protectors: true
  key_escrow_interval_hours: 24
  validate_key: true

logging:
  level: Info
  file_path: $configDir\logs\crypt.log
"@
    Set-Content -Path $configFile -Value $config -Encoding UTF8
    Write-Host "Created config file: $configFile" -ForegroundColor Green
}

# Register scheduled task for automatic key rotation
try {
    $cryptExe = Join-Path $installPath 'checkin.exe'
    if (Test-Path $cryptExe) {
        Write-Host "Registering daily scheduled task..." -ForegroundColor Cyan
        & $cryptExe register-task --frequency daily 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Scheduled task registered successfully" -ForegroundColor Green
        }
    }
} catch {
    Write-Host "Could not register scheduled task: $_" -ForegroundColor Yellow
}

Write-Host "`nCrypt installation complete!" -ForegroundColor Green
Write-Host "Usage: checkin --help" -ForegroundColor Cyan
if (-not (Test-Path $configFile)) {
    Write-Host "Configure: checkin config set server.url https://your-crypt-server" -ForegroundColor Yellow
}

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

# Create the data directory and lock it to administrators. The escrow task runs as
# SYSTEM and reads config.yaml and its state files from here, and a folder created
# under ProgramData would otherwise let any user add files to it.
if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    Write-Host "Created config directory: $configDir" -ForegroundColor Green
}

$dirItem = Get-Item -LiteralPath $configDir -Force
if ($dirItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    # A link in place of the folder would send every read and write somewhere else.
    $dirItem.Delete()
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    Write-Host "Replaced $configDir`: it was a link" -ForegroundColor Yellow
}

$trustedOwners = @(
    'S-1-5-18',
    'S-1-5-32-544',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
)

# SYSTEM and Administrators full control, Users read, inheritance from ProgramData off.
& icacls.exe $configDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /Q | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Could not set permissions on $configDir (icacls exit $LASTEXITCODE)" -ForegroundColor Red
    exit 1
}
& icacls.exe $configDir /setowner '*S-1-5-32-544' /Q | Out-Null

# Anything below it that a non-administrator owns, or that is a link, could still be
# changed by whoever put it there: remove it. Logs are kept and taken back. Links are
# removed before anything is deleted recursively, and never followed.
$logsDir = Join-Path (Get-Item -LiteralPath $configDir -Force).FullName 'logs'
function Clear-UntrustedEntries([IO.DirectoryInfo]$Directory) {
    foreach ($item in $Directory.GetFileSystemInfos()) {
        try {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                $item.Delete()
                Write-Host "Removed $($item.FullName): a link" -ForegroundColor Yellow
                continue
            }
            if ($item -is [IO.DirectoryInfo]) {
                Clear-UntrustedEntries $item
            }
            $owner = (Get-Acl -LiteralPath $item.FullName).GetOwner([Security.Principal.SecurityIdentifier]).Value
            if ($trustedOwners -contains $owner) {
                continue
            }
            if ($item.FullName -eq $logsDir -or $item.FullName -like "$logsDir\*") {
                & icacls.exe $item.FullName /setowner '*S-1-5-32-544' /Q | Out-Null
            } else {
                if ($item -is [IO.DirectoryInfo]) { $item.Delete($true) } else { $item.Delete() }
                Write-Host "Removed $($item.FullName): not created by an administrator" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "Could not check $($item.FullName): $_" -ForegroundColor Yellow
        }
    }
}
Clear-UntrustedEntries (Get-Item -LiteralPath $configDir -Force)

# Children inherit the folder's ACL and nothing else.
& icacls.exe "$configDir\*" /reset /T /C /Q 2>&1 | Out-Null
Write-Host "Secured $configDir" -ForegroundColor Green

# Create logs directory
if (-not (Test-Path $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
}

# A server URL handed over in the machine environment goes into the machine settings
# key, which only administrators can write. Policy still overrides it.
$settingsKey = 'HKLM:\SOFTWARE\Crypt\ManagedEncryption\Settings'
$serverUrl = [Environment]::GetEnvironmentVariable('CRYPT_ESCROW_SERVER_URL', 'Machine')
if ($serverUrl) {
    if (-not (Test-Path $settingsKey)) {
        New-Item -Path $settingsKey -Force | Out-Null
    }
    if (-not (Get-ItemProperty -Path $settingsKey -Name 'ServerUrl' -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path $settingsKey -Name 'ServerUrl' -Value $serverUrl -PropertyType String -Force | Out-Null
        Write-Host "Configured Crypt server: $serverUrl" -ForegroundColor Green
    }
}

# Credentials live in a registry key only SYSTEM and Administrators can read. If its
# ACL cannot be set, the install fails rather than leave a credential readable.
$secretsPath = 'SOFTWARE\Crypt\ManagedEncryption\Secrets'
$trustedSids = @('S-1-5-18', 'S-1-5-32-544')
try {
    $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
    $secretsKey = $hklm.CreateSubKey($secretsPath, $true)
    $acl = New-Object System.Security.AccessControl.RegistrySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in $trustedSids) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier $sid),
            'FullControl', 'ContainerInherit', 'None', 'Allow')))
    }
    $secretsKey.SetAccessControl($acl)
    $applied = $secretsKey.GetAccessControl()
    $others = $applied.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
        Where-Object { $_.AccessControlType -eq 'Allow' -and $trustedSids -notcontains $_.IdentityReference.Value }
    if (-not $applied.AreAccessRulesProtected -or $others) {
        throw 'other accounts can still read it'
    }
    $secretsKey.Dispose()
    Write-Host "Secured HKLM\$secretsPath" -ForegroundColor Green
} catch {
    Write-Host "Could not protect HKLM\$secretsPath`: $_" -ForegroundColor Red
    exit 1
}

# Register scheduled task for automatic key rotation
try {
    $cryptExe = Join-Path $installPath 'checkin.exe'
    if (Test-Path $cryptExe) {
        Write-Host "Registering hourly scheduled task..." -ForegroundColor Cyan
        & $cryptExe register-task --frequency hourly 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Scheduled task registered successfully" -ForegroundColor Green
        }
    }
} catch {
    Write-Host "Could not register scheduled task: $_" -ForegroundColor Yellow
}

# Move any credential still in policy, settings, the machine environment or config.yaml
# into the protected store. Each copy is removed only after the store holds it.
$cryptExe = Join-Path $installPath 'checkin.exe'
if (Test-Path $cryptExe) {
    & $cryptExe migrate-secrets 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Some credentials could not be moved to the protected store; see the log" -ForegroundColor Yellow
    }
}

Write-Host "`nCrypt installation complete!" -ForegroundColor Green
Write-Host "Usage: checkin --help" -ForegroundColor Cyan
Write-Host "Configure: checkin config set server.url https://your-crypt-server (elevated), or by policy" -ForegroundColor Yellow

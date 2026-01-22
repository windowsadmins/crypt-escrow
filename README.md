# Crypt for Windows

BitLocker recovery key escrow to [Crypt Server](https://github.com/grahamgilbert/Crypt-Server) with full key rotation support.

A native Windows implementation inspired by the [Mac Crypt client](https://github.com/grahamgilbert/Crypt), built with .NET 10 for escrowing BitLocker recovery keys with automatic key rotation, enterprise logging, and scheduled task integration.

## Features

- Escrow BitLocker recovery keys to Crypt Server
- Full key rotation support (create new key, escrow, cleanup old keys)
- Automatic rotation when server requests it
- Verify escrow status via Crypt Server API
- YAML configuration file with environment variable fallback
- Windows scheduled task registration
- Structured logging with Serilog
- Single-file self-contained executable (no .NET runtime required)
- ARM64 and x64 native binaries
- Intune-compatible exit codes

### Mac Crypt-Inspired Features

- **KeyEscrowInterval**: Configurable re-escrow interval (default: 1 hour)
- **ValidateKey**: Local key validation before escrow
- **SkipUsers**: Array of users to skip from escrow enforcement
- **PostRunCommand**: Command to run after error conditions
- **Log Rotation**: Configurable log retention (default: 30 days)

## Installation

### Download Release

Download the latest release from [GitHub Releases](https://github.com/windowsadmins/crypt-escrow/releases):
- `crypt-x64.exe` - For Intel/AMD systems
- `crypt-arm64.exe` - For ARM64 systems (Surface Pro X, etc.)

### Build from Source

```powershell
# Full build with auto-signing (if certificate available)
.\build.ps1

# Build without signing
.\build.ps1 -NoSign

# Build specific architecture
.\build.ps1 -Runtime win-x64
```

## Quick Start

### 1. Configure the Server URL

```powershell
# Option A: Set via command
crypt config set server.url https://crypt.example.com

# Option B: Set via environment variable
setx CRYPT_ESCROW_SERVER_URL "https://crypt.example.com" /M
```

### 2. Escrow the BitLocker Key

```powershell
crypt escrow
```

### 3. Verify Escrow Status

```powershell
crypt verify
```

## Commands

### escrow

Escrows the BitLocker recovery key to the Crypt Server.

```powershell
crypt escrow [options]

Options:
  -s, --server <url>     Crypt Server URL
  -d, --drive <drive>    Drive letter (default: C:)
  -f, --force            Force escrow even if already escrowed
  --skip-cert-check      Skip TLS certificate validation
```

### rotate

Rotates the BitLocker recovery key and escrows the new key.

```powershell
crypt rotate [options]

Options:
  -s, --server <url>     Crypt Server URL
  -d, --drive <drive>    Drive letter (default: C:)
  -c, --cleanup          Remove old protectors (default: true)
  --skip-cert-check      Skip TLS certificate validation
```

### verify

Checks if a key has been escrowed for the current device.

```powershell
crypt verify [options]

Options:
  -s, --server <url>     Crypt Server URL
  --skip-cert-check      Skip TLS certificate validation
```

### config

Manage configuration settings.

```powershell
# Show current configuration
crypt config show

# Set a configuration value
crypt config set server.url https://crypt.example.com
crypt config set escrow.auto_rotate true
crypt config set escrow.key_escrow_interval_hours 2
```

### register-task

Registers a Windows scheduled task for automated escrow.

```powershell
crypt register-task [options]

Options:
  -s, --server <url>     Crypt Server URL
  -f, --frequency        Task frequency: hourly, daily, weekly, login (default: daily)
```

## Configuration

Configuration is loaded from (in order of precedence):
1. Command-line options
2. Environment variables
3. Registry (CSP/OMA-URI from Intune)
4. YAML configuration file

### Configuration File

Location: `C:\ProgramData\ManagedEncryption\config.yaml`

```yaml
server:
  url: https://crypt.example.com
  verify_ssl: true
  timeout_seconds: 30
  retry_attempts: 3

escrow:
  secret_type: recovery_key
  auto_rotate: true
  cleanup_old_protectors: true
  key_escrow_interval_hours: 1
  validate_key: true
  post_run_command: null
  skip_users:
    - admin
    - service_account

logging:
  level: INFO
  retained_days: 30
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `CRYPT_ESCROW_SERVER_URL` | Crypt Server URL |
| `CRYPT_ESCROW_SKIP_CERT_CHECK` | Skip SSL verification (true/false) |
| `CRYPT_ESCROW_AUTO_ROTATE` | Auto-rotate on server request |
| `CRYPT_ESCROW_CLEANUP_OLD_PROTECTORS` | Remove old protectors |
| `CRYPT_KEY_ESCROW_INTERVAL` | Re-escrow interval in hours |
| `CRYPT_VALIDATE_KEY` | Validate key locally before escrow |
| `CRYPT_SKIP_USERS` | Comma-separated list of users to skip |
| `CRYPT_POST_RUN_COMMAND` | Command to run after errors |

### Registry Configuration (CSP/OMA-URI)

Enterprise policies can be deployed via Intune CSP/OMA-URI to these registry locations:

**Standard Group Policy Path:**
`HKLM\SOFTWARE\Policies\Crypt\ManagedEncryption`

**MDM/Intune Path:**
`HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Crypt~Policy~ManagedEncryption`

| Value Name | Type | Description |
|------------|------|-------------|
| `ServerUrl` | String | Crypt Server URL (e.g., https://crypt.example.com) |
| `SkipCertCheck` | String/DWORD | Skip SSL verification (true/1 or false/0) |
| `AutoRotate` | String/DWORD | Auto-rotate on server request |
| `CleanupOldProtectors` | String/DWORD | Remove old protectors after escrow |
| `KeyEscrowIntervalHours` | String/DWORD | Re-escrow interval in hours |
| `ValidateKey` | String/DWORD | Validate key locally before escrow |
| `SkipUsers` | String | Comma-separated list of users to skip |
| `PostRunCommand` | String | Command to run after errors |

**Intune Custom OMA-URI Example:**
- OMA-URI: `./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Crypt/ManagedEncryption/ServerUrl`
- Data type: String
- Value: `https://crypt.example.com`

## Exit Codes

For Intune proactive remediation compatibility:

| Code | Meaning |
|------|---------|
| 0 | Success - key escrowed |
| 1 | BitLocker not enabled |
| 2 | No recovery password protector found |
| 3 | Network/server error (retry-able) |
| 4 | Configuration error |
| 5 | Key rotation failed |
| 10 | Already escrowed, no action needed |

## Intune Proactive Remediation

### Detection Script

```powershell
$result = & "C:\Program Files\Crypt\crypt.exe" verify
exit $LASTEXITCODE
```

### Remediation Script

```powershell
$result = & "C:\Program Files\Crypt\crypt.exe" escrow
exit $LASTEXITCODE
```

## Building

### Prerequisites

- .NET 10 SDK
- Windows SDK (for code signing, optional)

### Build Commands

```powershell
# Full build with auto-signing
.\build.ps1

# Build without signing
.\build.ps1 -NoSign

# Build with specific certificate
.\build.ps1 -Sign -CertificateName "Your Certificate CN"
.\build.ps1 -Sign -Thumbprint "CERTIFICATE_THUMBPRINT"

# Debug build
.\build.ps1 -Configuration Debug

# Single architecture
.\build.ps1 -Runtime win-x64
.\build.ps1 -Runtime win-arm64
```

### Code Signing

The build script automatically detects code signing certificates from the Windows certificate store. For CI/CD pipelines, set:

- `SIGNTOOL_PATH` - Path to signtool.exe
- Use `-CertificateName` or `-Thumbprint` to specify the certificate

## Logging

Logs are written to `C:\ProgramData\ManagedEncryption\Logs\CryptEscrow_YYYYMMDD.log`

Log rotation is automatic with configurable retention (default: 30 days).

## Requirements

- Windows 10/11 or Windows Server 2016+
- BitLocker enabled on target drive
- Administrator privileges
- Network access to Crypt Server

## Credits

Inspired by:
- [Crypt](https://github.com/grahamgilbert/Crypt) by Graham Gilbert (Mac client)
- [crypt-bde](https://github.com/bdemetris/crypt-bde) by Bryan Demetris
- [bitlocker2crypt](https://github.com/johnnyramos/bitlocker2crypt) by Johnny Ramos
- [Crypt-Server](https://github.com/grahamgilbert/Crypt-Server) by Graham Gilbert

## License

MIT License - see [LICENSE](LICENSE) for details.

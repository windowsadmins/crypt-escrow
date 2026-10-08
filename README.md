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
- `checkin-x64.exe` - For Intel/AMD systems
- `checkin-arm64.exe` - For ARM64 systems (Surface Pro X, etc.)

> **Note:** The binary is named `checkin` (following Mac Crypt convention). When installed via MSI, it is added to `PATH` as `checkin.exe` in `C:\Program Files\Crypt\`.

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
checkin config set server.url https://crypt.example.com

# Option B: Set via environment variable
setx CRYPT_ESCROW_SERVER_URL "https://crypt.example.com" /M
```

### 2. Escrow the BitLocker Key

```powershell
checkin escrow
```

### 3. Verify Escrow Status

```powershell
checkin verify
```

## Commands

### escrow

Escrows the BitLocker recovery key to the Crypt Server.

```powershell
checkin escrow [options]

Options:
  -s, --server <url>     Crypt Server URL
  -d, --drive <drive>    Drive letter (default: C:)
  -f, --force            Force escrow even if already escrowed
  --skip-cert-check      Skip TLS certificate validation
```

### rotate

Rotates the BitLocker recovery key and escrows the new key.

```powershell
checkin rotate [options]

Options:
  -s, --server <url>     Crypt Server URL
  -d, --drive <drive>    Drive letter (default: C:)
  -c, --cleanup          Remove old protectors (default: true)
  --skip-cert-check      Skip TLS certificate validation
```

### verify

Checks if a key has been escrowed for the current device.

```powershell
checkin verify [options]

Options:
  -s, --server <url>     Crypt Server URL
  --skip-cert-check      Skip TLS certificate validation
```

### config

Manage configuration settings.

```powershell
# Show current configuration
checkin config show

# Set a configuration value
checkin config set server.url https://crypt.example.com
checkin config set escrow.auto_rotate true
checkin config set escrow.key_escrow_interval_hours 2
```

### register-task

Registers a Windows scheduled task for automated escrow.

```powershell
checkin register-task [options]

Options:
  -s, --server <url>     Crypt Server URL
  -f, --frequency        Task frequency: hourly, daily, weekly, login (default: daily)
```

## Managed Encryption Escrow app

`Managed Encryption Escrow.exe` installs beside `checkin.exe` in `C:\Program Files\Crypt` and adds a Start menu shortcut. It has three tabs.

- **Prefs** shows every setting. It opens read-only; **Unlock** relaunches it as administrator, and changes then save to `HKLM\SOFTWARE\Crypt\ManagedEncryption\Settings`. A setting that policy sets shows the policy value and stays locked. The API key is never displayed: once unlocked, the tab only says whether one is saved. The PFX passphrase stays in Credential Manager and the app does not read it.
- **Run** runs one of three operations as administrator and streams its log: **Escrow now** (`escrow --force`), **Verify escrow** (`verify`) and **Rotate key** (`rotate`, after a confirmation; old keys are removed only if *Remove old recovery keys after rotation* is on).
- **Logs** lists the log folder one day per session, newest first, with lines coloured by level.

The app removes anything shaped like a BitLocker recovery password from what it displays.

## Configuration

Every setting is resolved through the same chain, highest first:
1. Command-line options for that run (`--server`, `--skip-cert-check`)
2. Policy: `HKLM\SOFTWARE\Policies\Crypt\ManagedEncryption`, then the Intune PolicyManager path `HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Crypt~Policy~ManagedEncryption`
3. Machine settings: `HKLM\SOFTWARE\Crypt\ManagedEncryption\Settings` (64-bit view), then the matching environment variable
4. The legacy YAML file `C:\ProgramData\ManagedEncryption\config.yaml`
5. Built-in defaults

Environment variables never override policy or machine settings. Every setting can be set by policy; the value names are listed in [docs/INTUNE-CSP-CONFIGURATION.md](docs/INTUNE-CSP-CONFIGURATION.md).

`checkin config show` prints each effective value and the layer it came from. `checkin config set <key> <value>`, run elevated, writes the machine settings key; a value set by policy still wins.

### Configuration File

Location: `C:\ProgramData\ManagedEncryption\config.yaml`

The file is a legacy source, read below policy and machine settings. The installer restricts `C:\ProgramData\ManagedEncryption` to SYSTEM and Administrators (full control) and Users (read), with inheritance from ProgramData turned off. The tool trusts `config.yaml`, `escrow.marker` and `last_escrow.txt` only while that folder is locked and no non-administrator can write, delete or re-permission the file; links are refused, and an ignored file is logged with the reason. Each run as SYSTEM also repairs the folder ACL and sets Administrators as the owner of anything an individual account owns. On the first lockdown of a folder that was open to every user, a file whose owner cannot be resolved as an administrator is moved to `quarantine\<timestamp>` rather than deleted.

```yaml
server:
  url: https://crypt.example.com
  verify_ssl: true
  timeout_seconds: 30
  retry_attempts: 3
  auth:
    api_key: your-secret-api-key
    api_key_header: X-API-Key
    use_mtls: false
    certificate_subject: crypt-client.example.com
    certificate_store_location: LocalMachine
    certificate_store_name: My

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

Environment variables sit in the machine settings layer, below the settings key and above the YAML file.

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
| `CRYPT_API_KEY` | API key for server authentication |
| `CRYPT_API_KEY_HEADER` | Custom API key header name (default: X-API-Key) |
| `CRYPT_USE_MTLS` | Enable mutual TLS authentication (true/false) |
| `CRYPT_CERT_SUBJECT` | Client certificate subject name for mTLS (Cert Store) |
| `CRYPT_CERT_THUMBPRINT` | Client certificate thumbprint for mTLS (Cert Store) |
| `CRYPT_PFX_PATH` | Path to client certificate PFX file for mTLS (preferred file-based option) |
| `CRYPT_PFX_PASSWORD_CRED` | Name of Windows Credential Manager entry holding the PFX passphrase |
| `CRYPT_CLIENT_CERT_PATH` | Path to client certificate PEM file for mTLS (least preferred file-based option) |
| `CRYPT_CLIENT_KEY_PATH` | Path to client private key PEM file (paired with above) |
| `CRYPT_CERT_STORE_LOCATION` | Certificate store location: LocalMachine or CurrentUser |
| `CRYPT_CERT_STORE_NAME` | Certificate store name (default: My) |
| `CRYPT_LOG_LEVEL` | Log level: DEBUG, INFO, WARN, ERROR |
| `CRYPT_LOG_FILE_PATH` | Log file path |
| `CRYPT_LOG_RETAINED_DAYS` | Days of logs to keep |

### Authentication

The client supports API key and mutual TLS (mTLS) authentication.

**API Key:**

The API key is kept in `HKLM\SOFTWARE\Crypt\ManagedEncryption\Secrets`, which only SYSTEM and Administrators can read. Set it with `checkin config set server.auth.api_key <key>` from an elevated prompt, or by policy. Each elevated run moves an API key it finds in a readable place into that key: the policy keys, the settings key, the machine `CRYPT_API_KEY` variable or `config.yaml`. The value is written and read back before the readable copy is removed. A policy copy is blanked rather than deleted, so the setting still shows as managed, and a value from a lower layer never replaces one that came from policy.

The older forms below are still read until that move happens:

```yaml
server:
  auth:
    api_key: your-secret-api-key
    api_key_header: X-API-Key  # custom header name (default)
```

Or via environment variables: `CRYPT_API_KEY` and `CRYPT_API_KEY_HEADER`.

**Mutual TLS (mTLS):**

Set `use_mtls: true` (or `CRYPT_USE_MTLS=true`) and pick one of the three strategies below. They are tried in the order listed — most secure first — and the first one that succeeds wins. If you configure multiple, the higher-ranked strategy is used.

#### 1. Windows Certificate Store (preferred)

Similar to Mac Crypt's `CommonNameForEscrow` feature. The private key is protected by DPAPI, can be marked non-exportable at import time, and integrates with the Windows PKI lifecycle. Deployable via Intune / Group Policy.

```yaml
server:
  auth:
    use_mtls: true
    certificate_subject: crypt-client.example.com  # or use certificate_thumbprint
    certificate_store_location: LocalMachine        # or CurrentUser
    certificate_store_name: My
```

Environment variables: `CRYPT_CERT_SUBJECT`, `CRYPT_CERT_THUMBPRINT`.

#### 2. PFX file + Credential Manager passphrase

Use when importing into the Cert Store isn't feasible but you still want encrypted-at-rest key material. The passphrase lives in Windows Credential Manager (DPAPI-protected) and is **never** stored in YAML, environment variables, or the registry.

Provision the passphrase once with `cmdkey`:

```cmd
cmdkey /generic:CryptPfxPassword /user:cryptescrow /pass:<pfx-passphrase>
```

Then configure:

```yaml
server:
  auth:
    use_mtls: true
    pfx_path: C:\ProgramData\ManagedEncryption\client.pfx
    pfx_password_credential: CryptPfxPassword  # matches the /generic: value above
```

Environment variables: `CRYPT_PFX_PATH`, `CRYPT_PFX_PASSWORD_CRED`. If the PFX has no passphrase, omit `pfx_password_credential`.

#### 3. PEM + .key file (least preferred)

The private key sits in plaintext on disk, protected only by filesystem ACLs. Only use this when the other two options aren't available, and lock the key file down so only `SYSTEM` (or the service account) can read it:

```cmd
icacls C:\ProgramData\ManagedEncryption\client.key /inheritance:r /grant:r SYSTEM:R
```

```yaml
server:
  auth:
    use_mtls: true
    client_cert_path: C:\ProgramData\ManagedEncryption\client.pem
    client_key_path:  C:\ProgramData\ManagedEncryption\client.key
```

Environment variables: `CRYPT_CLIENT_CERT_PATH`, `CRYPT_CLIENT_KEY_PATH`.

### Registry Configuration (CSP/OMA-URI)

Enterprise policies are read from these registry locations:

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
| `ApiKey` | String | API key for server authentication |
| `ApiKeyHeader` | String | Custom API key header name (default: X-API-Key) |
| `UseMtls` | String/DWORD | Enable mutual TLS authentication (true/1 or false/0) |
| `CertificateSubject` | String | Client certificate subject name for mTLS |
| `CertificateThumbprint` | String | Client certificate thumbprint for mTLS |
| `PfxPath` | String | Path to client PFX file (preferred file-based mTLS option) |
| `PfxPasswordCredential` | String | Windows Credential Manager target name holding the PFX passphrase |
| `ClientCertPath` | String | Path to client certificate PEM file (least preferred file-based mTLS option) |
| `ClientKeyPath` | String | Path to client private key PEM file (paired with `ClientCertPath`) |

**Policy template:** `resources/Crypt.admx` and `resources/en-US/Crypt.adml` cover every setting, for Group Policy or for Intune (Import ADMX, or ADMX ingestion with custom OMA-URIs). Each release attaches them as `Crypt-PolicyTemplates.zip`. [docs/INTUNE-CSP-CONFIGURATION.md](docs/INTUNE-CSP-CONFIGURATION.md) lists the OMA-URI for each policy.

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
| 6 | Insufficient permissions (requires administrator) |
| 7 | Authentication failed (invalid or missing API key) |
| 10 | Already escrowed, no action needed |

## Intune Proactive Remediation

### Detection Script

```powershell
$result = & "C:\Program Files\Crypt\checkin.exe" verify
exit $LASTEXITCODE
```

### Remediation Script

```powershell
$result = & "C:\Program Files\Crypt\checkin.exe" escrow
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

Logs are written to `C:\ProgramData\ManagedEncryption\logs\crypt-escrow.log`, rolled daily
with the date appended to the rolled file name and 30 files kept by default. Each line is
`[yyyy-MM-dd HH:mm:ss] LEVEL  message` in local time, with the level one of `DEBUG`, `INFO`,
`WARN` or `ERROR`.

Override the location, level and how many days are kept with the `logging` section of
`config.yaml` (`file_path`, `level`, `retained_days`). Pass `-v`/`--verbose` to any command to
log at Debug level to both the console and the file for that run.

## Requirements

- Windows 10/11 or Windows Server 2016+
- BitLocker enabled on target drive
- Administrator privileges
- Network access to Crypt Server

## Additional Documentation

- [Intune CSP/OMA-URI Configuration Guide](docs/INTUNE-CSP-CONFIGURATION.md) — detailed Intune setup with OMA-URI examples and PowerShell scripts
- [Deployment Guide](deploy/DEPLOYMENT.md) — Cimian deployment, testing, and monitoring
- [Changelog](CHANGELOG.md) — version history
- [Example Configuration](examples/config.example.yaml) — fully commented config template

## Credits

Inspired by:
- [Crypt](https://github.com/grahamgilbert/Crypt) by Graham Gilbert (Mac client)
- [crypt-bde](https://github.com/bdemetris/crypt-bde) by Bryan Demetris
- [bitlocker2crypt](https://github.com/johnnyramos/bitlocker2crypt) by Johnny Ramos
- [Crypt-Server](https://github.com/grahamgilbert/Crypt-Server) by Graham Gilbert

## License

MIT License - see [LICENSE](LICENSE) for details.

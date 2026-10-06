# Intune CSP/OMA-URI Configuration for CryptEscrow

This document provides guidance for deploying CryptEscrow configuration via Microsoft Intune using CSP (Configuration Service Provider) and OMA-URI registry settings.

## Overview

CryptEscrow supports enterprise configuration through Windows registry, allowing centralized management via Intune without requiring YAML config files on each device.

## Configuration Hierarchy

Settings are evaluated in this order (highest to lowest priority):

1. **Command-line options** - `--server` and `--skip-cert-check` for that run
2. **Policy** - the Group Policy path, then the Intune PolicyManager path below
3. **Machine settings** - `HKLM\SOFTWARE\Crypt\ManagedEncryption\Settings` (64-bit view, written by `checkin config set` run elevated), then the matching `CRYPT_*` environment variable
4. **YAML config file** - `C:\ProgramData\ManagedEncryption\config.yaml`, only while it and its folder are writable by SYSTEM and Administrators alone
5. **Built-in defaults**

Environment variables never override policy. A policy value that cannot be parsed (for example a non-numeric `KeyEscrowIntervalHours`) is skipped and the next layer applies.

## Registry Paths

CryptEscrow checks both standard Group Policy and MDM paths:

### Standard Group Policy Path
```
HKLM\SOFTWARE\Policies\Crypt\ManagedEncryption
```

### MDM/Intune PolicyManager Path
```
HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Crypt~Policy~ManagedEncryption
```

## Supported Registry Values

| Value Name | Type | Description | Example |
|------------|------|-------------|---------|
| `ServerUrl` | REG_SZ | Crypt server URL | `https://crypt.example.org` |
| `SkipCertCheck` | REG_SZ or REG_DWORD | Skip SSL verification | `false` or `0` |
| `AutoRotate` | REG_SZ or REG_DWORD | Auto-rotate on server request | `true` or `1` |
| `CleanupOldProtectors` | REG_SZ or REG_DWORD | Remove old protectors after escrow | `true` or `1` |
| `KeyEscrowIntervalHours` | REG_SZ or REG_DWORD | Re-escrow interval in hours | `24` |
| `ValidateKey` | REG_SZ or REG_DWORD | Validate key locally before escrow | `true` or `1` |
| `SkipUsers` | REG_SZ | Comma-separated list of users to skip | `admin,service` |
| `PostRunCommand` | REG_SZ | Command to run after errors | `shutdown /r /t 300` |
| `ApiKey` | REG_SZ | API key for server authentication | |
| `ApiKeyHeader` | REG_SZ | API key header name | `X-API-Key` |
| `UseMtls` | REG_SZ or REG_DWORD | Use mutual TLS | `true` or `1` |
| `CertificateSubject` | REG_SZ | Client certificate subject (certificate store) | `crypt-client.example.org` |
| `CertificateThumbprint` | REG_SZ | Client certificate thumbprint (certificate store) | |
| `CertificateStoreLocation` | REG_SZ | `LocalMachine` or `CurrentUser` | `LocalMachine` |
| `CertificateStoreName` | REG_SZ | Certificate store name | `My` |
| `PfxPath` | REG_SZ | Client certificate PFX file | `C:\ProgramData\ManagedEncryption\client.pfx` |
| `PfxPasswordCredential` | REG_SZ | Credential Manager entry holding the PFX passphrase | `CryptPfxPassword` |
| `ClientCertPath` | REG_SZ | Client certificate PEM file | |
| `ClientKeyPath` | REG_SZ | Client private key PEM file | |
| `LogLevel` | REG_SZ | `DEBUG`, `INFO`, `WARN`, `ERROR` | `INFO` |
| `LogFilePath` | REG_SZ | Log file path | |
| `LogRetainedDays` | REG_SZ or REG_DWORD | Days of logs to keep | `30` |

The same value names are read from the machine settings key, `HKLM\SOFTWARE\Crypt\ManagedEncryption\Settings`.

## Intune Configuration

### Option 1: Custom OMA-URI (Recommended)

Create a custom Device Configuration profile:

1. Navigate to: **Devices** > **Configuration profiles** > **Create profile**
2. Platform: **Windows 10 and later**
3. Profile type: **Templates** > **Custom**
4. Add OMA-URI settings as shown below

#### ServerUrl Configuration

- **Name**: Crypt Server URL
- **OMA-URI**: `./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Crypt/ManagedEncryption/ServerUrl`
- **Data type**: String
- **Value**: `https://crypt.example.org`

#### SkipCertCheck Configuration

- **Name**: Crypt Skip Certificate Check
- **OMA-URI**: `./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Crypt/ManagedEncryption/SkipCertCheck`
- **Data type**: String
- **Value**: `false`

#### AutoRotate Configuration

- **Name**: Crypt Auto-Rotate Keys
- **OMA-URI**: `./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Crypt/ManagedEncryption/AutoRotate`
- **Data type**: String
- **Value**: `true`

#### CleanupOldProtectors Configuration

- **Name**: Crypt Cleanup Old Protectors
- **OMA-URI**: `./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Crypt/ManagedEncryption/CleanupOldProtectors`
- **Data type**: String
- **Value**: `true`

#### KeyEscrowIntervalHours Configuration

- **Name**: Crypt Key Escrow Interval
- **OMA-URI**: `./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Crypt/ManagedEncryption/KeyEscrowIntervalHours`
- **Data type**: Integer
- **Value**: `24`

#### ValidateKey Configuration

- **Name**: Crypt Validate Key
- **OMA-URI**: `./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Crypt/ManagedEncryption/ValidateKey`
- **Data type**: String
- **Value**: `true`

#### SkipUsers Configuration

- **Name**: Crypt Skip Users
- **OMA-URI**: `./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Crypt/ManagedEncryption/SkipUsers`
- **Data type**: String
- **Value**: `admin,localadmin`

### Option 2: PowerShell Script

Deploy via Intune PowerShell script:

```powershell
# Set Crypt enterprise configuration
$regPath = 'HKLM:\SOFTWARE\Policies\Crypt\ManagedEncryption'

# Create registry key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set configuration values
Set-ItemProperty -Path $regPath -Name 'ServerUrl' -Value 'https://crypt.example.org' -Type String
Set-ItemProperty -Path $regPath -Name 'SkipCertCheck' -Value 'false' -Type String
Set-ItemProperty -Path $regPath -Name 'AutoRotate' -Value 'true' -Type String
Set-ItemProperty -Path $regPath -Name 'CleanupOldProtectors' -Value 'true' -Type String
Set-ItemProperty -Path $regPath -Name 'KeyEscrowIntervalHours' -Value '24' -Type String
Set-ItemProperty -Path $regPath -Name 'ValidateKey' -Value 'true' -Type String

Write-Host "CryptEscrow registry configuration completed successfully"
```

Deploy as:
- Script settings: **Run this script using the logged on credentials**: No (run as SYSTEM)
- **Run script in 64-bit PowerShell**: Yes

### Option 3: Group Policy (On-Premises AD)

For hybrid environments with on-premises Active Directory:

1. Create a Group Policy Object
2. Navigate to: **Computer Configuration** > **Preferences** > **Windows Settings** > **Registry**
3. Add registry items for each configuration value under:
   - Hive: `HKEY_LOCAL_MACHINE`
   - Key path: `SOFTWARE\Policies\Crypt\ManagedEncryption`
   - Value name: (as per table above)
   - Value type: REG_SZ or REG_DWORD
   - Value data: (as per table above)

## Verification

### Check Registry Configuration

```powershell
# View all CryptEscrow registry settings
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Crypt\ManagedEncryption' -ErrorAction SilentlyContinue

# Check MDM path
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Crypt~Policy~ManagedEncryption' -ErrorAction SilentlyContinue
```

### Test Configuration

```powershell
# Run in check mode to see current configuration
& 'C:\Program Files\Crypt\checkin.exe' check

# Run with verbose logging to see config source
& 'C:\Program Files\Crypt\checkin.exe' escrow --verbose
```

### View Logs

Configuration source is logged when settings are loaded:

```powershell
Get-Content 'C:\ProgramData\ManagedEncryption\logs\crypt-escrow.log' | Select-String 'registry'
```

## Best Practices

1. **Use OMA-URI for cloud-only environments** - Most reliable for Intune-managed devices
2. **Set minimal required configuration** - Only configure ServerUrl if using defaults for other settings
3. **Test in pilot group first** - Deploy to test devices before organization-wide rollout
4. **Monitor compliance** - Use Intune proactive remediation to verify key escrow status
5. **Document your settings** - Keep track of configured values for troubleshooting
6. **Use string values** - For boolean settings, use "true"/"false" strings rather than DWORD for clarity
7. **Avoid mixing config sources** - Choose either registry or YAML files, not both

## Troubleshooting

### Registry Not Being Read

1. Verify registry path exists and values are set correctly
2. Check that CryptEscrow has permission to read registry (runs as SYSTEM)
3. Enable debug logging to see configuration source
4. Check logs for registry read errors

### Configuration Not Applied

1. Verify Intune policy is assigned to correct group
2. Check device sync status: `dsregcmd /status`
3. Force Intune sync: **Settings** > **Accounts** > **Access work or school** > **Info** > **Sync**
4. Verify registry values on target device
5. Check CryptEscrow version supports registry configuration

### Priority Issues

Remember the configuration hierarchy:
- CLI options override everything
- Policy overrides machine settings, environment variables and YAML
- Machine settings override environment variables and YAML
- `checkin config show` prints the layer each value came from

If a setting isn't being applied, check higher-priority sources first.

## Example: Complete Intune Profile

Create a JSON file for bulk import:

```json
{
  "displayName": "CryptEscrow - BitLocker Key Escrow Configuration",
  "description": "Enterprise configuration for CryptEscrow BitLocker key escrow to crypt.example.org",
  "omaSettings": [
    {
      "@odata.type": "#microsoft.graph.omaSettingString",
      "displayName": "Crypt Server URL",
      "omaUri": "./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Crypt/ManagedEncryption/ServerUrl",
      "value": "https://crypt.example.org"
    },
    {
      "@odata.type": "#microsoft.graph.omaSettingString",
      "displayName": "Crypt Skip Certificate Check",
      "omaUri": "./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Crypt/ManagedEncryption/SkipCertCheck",
      "value": "false"
    },
    {
      "@odata.type": "#microsoft.graph.omaSettingString",
      "displayName": "Crypt Auto-Rotate Keys",
      "omaUri": "./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Crypt/ManagedEncryption/AutoRotate",
      "value": "true"
    },
    {
      "@odata.type": "#microsoft.graph.omaSettingString",
      "displayName": "Crypt Cleanup Old Protectors",
      "omaUri": "./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Crypt/ManagedEncryption/CleanupOldProtectors",
      "value": "true"
    },
    {
      "@odata.type": "#microsoft.graph.omaSettingInteger",
      "displayName": "Crypt Key Escrow Interval Hours",
      "omaUri": "./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Crypt/ManagedEncryption/KeyEscrowIntervalHours",
      "value": 24
    },
    {
      "@odata.type": "#microsoft.graph.omaSettingString",
      "displayName": "Crypt Validate Key",
      "omaUri": "./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Crypt/ManagedEncryption/ValidateKey",
      "value": "true"
    }
  ]
}
```

## References

- [Microsoft Intune OMA-URI Settings](https://learn.microsoft.com/en-us/mem/intune/configuration/custom-settings-windows-10)
- [Registry CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/registry-csp)
- [CryptEscrow Documentation](../README.md)
- [Crypt Server Project](https://github.com/grahamgilbert/Crypt-Server)

# Intune CSP/OMA-URI Configuration for CryptEscrow

This document provides guidance for deploying CryptEscrow configuration with the bundled ADMX policy template, through Microsoft Intune or Group Policy.

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

CryptEscrow reads policy from the standard Group Policy path, which is where the ADMX writes, whether it is applied by Group Policy or ingested by Intune. It then reads the PolicyManager path, for values written there directly:

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
| `ApiKey` | REG_SZ | API key for server authentication. The first elevated run moves it to `HKLM\SOFTWARE\Crypt\ManagedEncryption\Secrets` (SYSTEM and Administrators only) and blanks the policy copy. | |
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

## Policy template (ADMX)

The repository ships an administrative template that covers every setting:

- `resources/Crypt.admx`
- `resources/en-US/Crypt.adml`

Each release also attaches both files as `Crypt-PolicyTemplates.zip`.

Every policy writes to `HKLM\SOFTWARE\Policies\Crypt\ManagedEncryption`, under the value name in the table above. On/off settings write `REG_DWORD` 1 (Enabled) or 0 (Disabled), numbers write `REG_DWORD`, and text and choice settings write `REG_SZ`. A policy that is Not Configured writes nothing, so the machine setting or the default applies. The policies sit under **Managed Encryption (Crypt)**, in the same four groups the app's Prefs tab uses: Connection, Escrow, Authentication and Logging. Any setting a policy sets is locked in the Prefs tab.

`ValidateKey`, `SkipUsers` and `PostRunCommand` are read and shown, but this version of the client does not act on them yet.

### API key by policy

The `ApiKey` policy exists for organisations that accept the exposure. The first elevated run of `checkin` moves the key into `HKLM\SOFTWARE\Crypt\ManagedEncryption\Secrets`, which only SYSTEM and Administrators can read, and blanks the policy value. Until that run, the key in the policy key is readable by any user on the device, and it is readable again whenever Group Policy or MDM writes the value back. An MDM-delivered value may also be kept in the device's MDM policy store. Prefer a client certificate where you can.

## Intune Configuration

### Option 1: Import the ADMX (recommended)

1. In the Intune admin center, go to **Devices** > **Configuration** > **Import ADMX**.
2. Upload `Crypt.admx` and `en-US/Crypt.adml`.
3. Create a profile: **Windows 10 and later** > **Templates** > **Imported Administrative templates**, and configure the settings under **Managed Encryption (Crypt)**.

### Option 2: ADMX ingestion with custom OMA-URIs

Create a **Custom** profile for **Windows 10 and later**. The first row ingests the template. Its OMA-URI uses the app name `Crypt` and the setting type `Policy`:

- **OMA-URI**: `./Device/Vendor/MSFT/Policy/ConfigOperations/ADMXInstall/Crypt/Policy/CryptAdmx`
- **Data type**: String
- **Value**: the full contents of `Crypt.admx`

Then add one String row per setting. The category path in each OMA-URI is `ManagedEncryption` followed by the group:

| Policy | OMA-URI (after `./Device/Vendor/MSFT/Policy/Config/`) | Example value |
|---|---|---|
| ServerUrl | `Crypt~Policy~ManagedEncryption~Connection/ServerUrl` | `<enabled/><data id="ServerUrl_Value" value="https://crypt.example.com"/>` |
| SkipCertCheck | `Crypt~Policy~ManagedEncryption~Connection/SkipCertCheck` | `<enabled/>` or `<disabled/>` |
| AutoRotate | `Crypt~Policy~ManagedEncryption~Escrow/AutoRotate` | `<enabled/>` or `<disabled/>` |
| CleanupOldProtectors | `Crypt~Policy~ManagedEncryption~Escrow/CleanupOldProtectors` | `<enabled/>` or `<disabled/>` |
| ValidateKey | `Crypt~Policy~ManagedEncryption~Escrow/ValidateKey` | `<enabled/>` or `<disabled/>` |
| KeyEscrowIntervalHours | `Crypt~Policy~ManagedEncryption~Escrow/KeyEscrowIntervalHours` | `<enabled/><data id="KeyEscrowIntervalHours_Value" value="24"/>` |
| SkipUsers | `Crypt~Policy~ManagedEncryption~Escrow/SkipUsers` | `<enabled/><data id="SkipUsers_Value" value="admin,localadmin"/>` |
| PostRunCommand | `Crypt~Policy~ManagedEncryption~Escrow/PostRunCommand` | `<enabled/><data id="PostRunCommand_Value" value="shutdown /r /t 300"/>` |
| ApiKey | `Crypt~Policy~ManagedEncryption~Authentication/ApiKey` | `<enabled/><data id="ApiKey_Value" value="your-api-key"/>` |
| ApiKeyHeader | `Crypt~Policy~ManagedEncryption~Authentication/ApiKeyHeader` | `<enabled/><data id="ApiKeyHeader_Value" value="X-API-Key"/>` |
| UseMtls | `Crypt~Policy~ManagedEncryption~Authentication/UseMtls` | `<enabled/>` or `<disabled/>` |
| CertificateSubject | `Crypt~Policy~ManagedEncryption~Authentication/CertificateSubject` | `<enabled/><data id="CertificateSubject_Value" value="crypt-client.example.com"/>` |
| CertificateThumbprint | `Crypt~Policy~ManagedEncryption~Authentication/CertificateThumbprint` | `<enabled/><data id="CertificateThumbprint_Value" value="0123456789ABCDEF0123456789ABCDEF01234567"/>` |
| CertificateStoreLocation | `Crypt~Policy~ManagedEncryption~Authentication/CertificateStoreLocation` | `<enabled/><data id="CertificateStoreLocation_Value" value="LocalMachine"/>` |
| CertificateStoreName | `Crypt~Policy~ManagedEncryption~Authentication/CertificateStoreName` | `<enabled/><data id="CertificateStoreName_Value" value="My"/>` |
| PfxPath | `Crypt~Policy~ManagedEncryption~Authentication/PfxPath` | `<enabled/><data id="PfxPath_Value" value="C:\ProgramData\ManagedEncryption\client.pfx"/>` |
| PfxPasswordCredential | `Crypt~Policy~ManagedEncryption~Authentication/PfxPasswordCredential` | `<enabled/><data id="PfxPasswordCredential_Value" value="CryptPfxPassword"/>` |
| ClientCertPath | `Crypt~Policy~ManagedEncryption~Authentication/ClientCertPath` | `<enabled/><data id="ClientCertPath_Value" value="C:\ProgramData\ManagedEncryption\client.crt"/>` |
| ClientKeyPath | `Crypt~Policy~ManagedEncryption~Authentication/ClientKeyPath` | `<enabled/><data id="ClientKeyPath_Value" value="C:\ProgramData\ManagedEncryption\client.key"/>` |
| LogLevel | `Crypt~Policy~ManagedEncryption~Logging/LogLevel` | `<enabled/><data id="LogLevel_Value" value="INFO"/>` |
| LogFilePath | `Crypt~Policy~ManagedEncryption~Logging/LogFilePath` | `<enabled/><data id="LogFilePath_Value" value="C:\ProgramData\ManagedEncryption\logs\crypt-escrow.log"/>` |
| LogRetainedDays | `Crypt~Policy~ManagedEncryption~Logging/LogRetainedDays` | `<enabled/><data id="LogRetainedDays_Value" value="30"/>` |

On/off policies take `<enabled/>` or `<disabled/>` with no data. To pick a choice, the `value` is the choice itself, for example `CurrentUser` or `DEBUG`.

Ingested policies are written to `HKLM\SOFTWARE\Policies\Crypt\ManagedEncryption`, the first path the client reads. Their state in the PolicyManager store is kept under the group's own key, such as `Crypt~Policy~ManagedEncryption~Connection`, not under `Crypt~Policy~ManagedEncryption`.

### Option 3: PowerShell Script

Deploy via Intune PowerShell script:

```powershell
$regPath = 'HKLM:\SOFTWARE\Policies\Crypt\ManagedEncryption'
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name 'ServerUrl' -Value 'https://crypt.example.org' -Type String
Set-ItemProperty -Path $regPath -Name 'SkipCertCheck' -Value 0 -Type DWord
Set-ItemProperty -Path $regPath -Name 'AutoRotate' -Value 1 -Type DWord
Set-ItemProperty -Path $regPath -Name 'CleanupOldProtectors' -Value 1 -Type DWord
Set-ItemProperty -Path $regPath -Name 'KeyEscrowIntervalHours' -Value 24 -Type DWord
```

Deploy as:
- Script settings: **Run this script using the logged on credentials**: No (run as SYSTEM)
- **Run script in 64-bit PowerShell**: Yes

### Option 4: Group Policy (On-Premises AD)

1. Copy `Crypt.admx` to the central store, `\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions`, and `en-US\Crypt.adml` to its `en-US` folder. For local Group Policy, use `C:\Windows\PolicyDefinitions` instead.
2. In a Group Policy Object, go to **Computer Configuration** > **Policies** > **Administrative Templates** > **Managed Encryption (Crypt)**.

## Verification

### Check Registry Configuration

List the values policy has written:

```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Crypt\ManagedEncryption' -ErrorAction SilentlyContinue
```

### Test Configuration

Show every effective setting and the layer it came from:

```powershell
& 'C:\Program Files\Crypt\checkin.exe' config show
```

Run an escrow with verbose logging:

```powershell
& 'C:\Program Files\Crypt\checkin.exe' escrow --verbose
```

### View Logs

Each day's log is in its own folder under `C:\ProgramData\ManagedEncryption\logs`. Open the newest:

```powershell
Get-ChildItem 'C:\ProgramData\ManagedEncryption\logs' -Recurse -Filter 'crypt-escrow.log' | Sort-Object LastWriteTime | Select-Object -Last 1 | Get-Content
```

## Best Practices

1. **Use the ADMX** - Imported or ingested in Intune, or in the Group Policy central store
2. **Set minimal required configuration** - Only configure ServerUrl if using defaults for other settings
3. **Test in pilot group first** - Deploy to test devices before organization-wide rollout
4. **Monitor compliance** - Use Intune proactive remediation to verify key escrow status
5. **Document your settings** - Keep track of configured values for troubleshooting
6. **Prefer REG_DWORD for on/off settings** - The ADMX writes 1 or 0; `true`/`false` strings are also accepted
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

## References

- [Microsoft Intune OMA-URI Settings](https://learn.microsoft.com/en-us/mem/intune/configuration/custom-settings-windows-10)
- [Win32 and Desktop Bridge app ADMX policy ingestion](https://learn.microsoft.com/en-us/windows/client-management/win32-and-centennial-app-policy-configuration)
- [Import custom ADMX and ADML templates into Intune](https://learn.microsoft.com/en-us/mem/intune/configuration/administrative-templates-import-custom)
- [CryptEscrow Documentation](../README.md)
- [Crypt Server Project](https://github.com/grahamgilbert/Crypt-Server)

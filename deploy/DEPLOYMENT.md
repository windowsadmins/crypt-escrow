# Crypt Deployment Guide

## Quick Start

1. **Copy packages to Cimian repo:**
   ```powershell
   # Copy .pkg files
   Copy-Item pkgs\Crypt-*.pkg ..\..\deployment\pkgs\security\
   
   # Copy pkgsinfo manifests
   Copy-Item deploy\Crypt-*.yaml ..\..\deployment\pkgsinfo\security\
   ```

2. **Configure Crypt Server URL:**
   The pkgsinfo files are pre-configured with: `https://crypt.ecuad.ca`
   Edit the yaml files if you need to change this.

3. **Deploy via Intune/Configuration Manager:**
   - Add to catalog: `Testing` first, then `Production`
   - Devices will auto-install on next Cimian sync
   - Task will run daily to rotate and escrow keys

## Manual Testing

Test on a BitLocker-enabled device:

```powershell
# Test escrow
crypt escrow --server https://crypt.ecuad.ca

# Test verification
crypt verify --server https://crypt.ecuad.ca

# Test rotation
crypt rotate --server https://crypt.ecuad.ca

# View config
crypt config show

# Register scheduled task
crypt register-task --frequency daily
```

## Architecture Support

- **x64**: Standard Intel/AMD 64-bit systems
- **arm64**: ARM64-based Surface devices and VMs

## Configuration Options

Set via config file (`C:\ProgramData\CryptEscrow\config.yaml`) or environment variables:

- `CRYPT_ESCROW_SERVER_URL`: Crypt server URL
- `CRYPT_KEY_ESCROW_INTERVAL`: Hours between rotations (default: 24)
- `CRYPT_VALIDATE_KEY`: Verify key after escrow (true/false)
- `CRYPT_SKIP_USERS`: Skip escrow for specific users (comma-separated)
- `CRYPT_POST_RUN_COMMAND`: Command to run after escrow

## Monitoring

Logs are written to: `C:\ProgramData\CryptEscrow\logs\crypt.log`

Check scheduled task: `Get-ScheduledTask -TaskName "Crypt BitLocker Key Rotation"`

## Crypt Server Requirements

- Crypt Server 3.x or later (https://github.com/grahamgilbert/Crypt-Server)
- TLS certificate (or use `--skip-cert-check` for testing)
- API endpoint accessible from managed devices

## Troubleshooting

```powershell
# Check if BitLocker is enabled
Get-BitLockerVolume -MountPoint C:

# View current recovery keys
(Get-BitLockerVolume -MountPoint C:).KeyProtector

# Test connectivity
Test-NetConnection crypt.ecuad.ca -Port 443

# Run with verbose logging
$env:CRYPT_LOG_LEVEL = 'Debug'
crypt escrow --server https://crypt.ecuad.ca
```

## Deployment Timeline

1. **Week 1**: Deploy to Testing catalog (pilot devices)
2. **Week 2**: Monitor and validate escrow in Crypt Server
3. **Week 3**: Promote to Production catalog (full fleet)
4. **Week 4**: Verify 100% fleet coverage

Built: 2026.01.21.0927

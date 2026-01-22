# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-01-20

### Changed
- Renamed CLI from `crypt-escrow` to `crypt` for simpler usage
- Updated artifact names: `crypt-x64.exe`, `crypt-arm64.exe`

### Added
- Mac Crypt-inspired configuration options:
  - `key_escrow_interval_hours` - Configurable re-escrow interval
  - `validate_key` - Local key validation before escrow
  - `skip_users` - Array of users to skip from escrow enforcement
  - `post_run_command` - Command to run after error conditions
  - `retained_days` - Configurable log retention
- New environment variables:
  - `CRYPT_KEY_ESCROW_INTERVAL`
  - `CRYPT_VALIDATE_KEY`
  - `CRYPT_SKIP_USERS`
  - `CRYPT_POST_RUN_COMMAND`
- `build.ps1` script with code signing support
  - Auto-detects certificates from Windows certificate store
  - Multiple timestamp server fallback
  - Configurable via `-CertificateName` or `-Thumbprint`

## [1.0.0] - 2026-01-20

### Added
- Initial release
- Native .NET 10 Windows application
- `escrow` command - Escrow BitLocker recovery key to Crypt Server
- `rotate` command - Full key rotation with new protector creation
- `verify` command - Check escrow status via Crypt Server API
- `register-task` command - Windows scheduled task registration
- `config show` / `config set` - Configuration management
- YAML configuration file support
- Environment variable configuration fallback
- Exponential backoff retry logic for network failures
- Structured logging with Serilog
- Single-file self-contained executables (x64 and ARM64)
- Intune-compatible exit codes
- Automatic key rotation when server requests it

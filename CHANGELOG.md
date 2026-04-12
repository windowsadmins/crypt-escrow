# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-04-11

Rollup of four PRs merged on the same day, covering a major mTLS
feature contributed by an external contributor, a full xUnit test
suite, CI modernization, and a pre-existing registry bug fix surfaced
by the Copilot review of the test suite PR.

This version corresponds to four CI-generated releases on `main`:

- [`v2026.04.11.2308`](https://github.com/windowsadmins/crypt-escrow/releases/tag/v2026.04.11.2308) — mTLS client authentication (PR #2)
- [`v2026.04.11.2314`](https://github.com/windowsadmins/crypt-escrow/releases/tag/v2026.04.11.2314) — xUnit test suite (PR #3)
- [`v2026.04.11.2344`](https://github.com/windowsadmins/crypt-escrow/releases/tag/v2026.04.11.2344) — Node.js 24 opt-in for Actions (PR #5)
- [`v2026.04.11.2347`](https://github.com/windowsadmins/crypt-escrow/releases/tag/v2026.04.11.2347) — REG_DWORD handling fix, closes #4 (PR #6)

### Added

- **mTLS client certificate authentication** with three strategies,
  tried in priority order (most secure first). Contributed by
  [@aysiu](https://github.com/aysiu) in
  [#2](https://github.com/windowsadmins/crypt-escrow/pull/2), with
  maintainer tweaks layered on top.
  1. **Windows Certificate Store** (preferred) — looked up by
     `certificate_subject` or `certificate_thumbprint` in
     `LocalMachine\My` / `CurrentUser\My`. Private key is
     DPAPI-protected and can be marked non-exportable; deployable via
     Intune / Group Policy. This was the original implementation and
     remains the recommended path for production.
  2. **PFX file + passphrase from Credential Manager** — loads a
     `.pfx` from disk where the decryption passphrase is pulled from a
     Windows Credential Manager entry (DPAPI-protected). The
     passphrase never touches YAML, environment variables, or the
     registry. Provision with
     `cmdkey /generic:<name> /user:<anything> /pass:<secret>`.
  3. **PEM certificate + unencrypted key file** — contributed by
     [@aysiu](https://github.com/aysiu). Least preferred — private key
     sits in plaintext on disk protected only by filesystem ACLs. Kept
     for environments where importing into the Cert Store isn't
     feasible, with a documented `icacls` lock-down recipe.
- **New `Services/CredentialManager.cs`** — ~60 LOC `LibraryImport`
  wrapper over `advapi32!CredReadW`. Trim/AOT-friendly; no new NuGet
  dependency.
- **Four new `AuthConfig` fields**: `ClientCertPath`, `ClientKeyPath`,
  `PfxPath`, `PfxPasswordCredential`. All routed through the existing
  env-var → registry → YAML helper pattern so Intune CSP/OMA-URI
  deployment works for the new fields.
- **New env vars and registry values** documented in the README:
  `CRYPT_PFX_PATH`, `CRYPT_PFX_PASSWORD_CRED`, `CRYPT_CLIENT_CERT_PATH`,
  `CRYPT_CLIENT_KEY_PATH`.
- **`tests/CryptEscrow.Tests/` xUnit test project** with 39 tests
  covering `ConfigService` priority chains, `CryptServerClient` HTTP
  behavior, `CredentialManager` round-trip, and `GetClientCertificate`
  strategy ordering. Tests run in ~1 second and require no admin
  rights. CI now gates publishing on `dotnet test`.
- **22 additional regression tests** (61 total) added with the #6 fix
  — unit + integration + end-to-end coverage for DWORD/QWORD registry
  value conversion.
- **`[InternalsVisibleTo]` + three test seams** on production code:
  `CryptServerClient` internal test constructor accepting an
  `HttpMessageHandler`, `GetClientCertificate` promoted
  `private → internal`, and `ConfigService.ConfigPathOverride` +
  `RegistryReaderOverride` seams (both default null, zero production
  impact).

### Changed

- **`GetClientCertificate` strategy priority**: Cert Store is now
  tried before any file-based strategy, matching the documented
  security ranking. `LoadFromCertStore` short-circuits when neither
  thumbprint nor subject is configured, so file-only users pay no
  cost and don't get misleading error logs. (Surfaced by Copilot
  review of the test suite PR.)
- **Obsolete `new X509Certificate2(byte[])` ctor replaced** with
  `X509CertificateLoader.LoadPkcs12` (removes `SYSLIB0057` warning
  on .NET 9+). The PFX round-trip on Windows is still needed so
  `HttpClient` can use the private key during the TLS handshake;
  the byte buffer is now cleared after use, and the resulting cert
  is tracked on the instance so `Dispose()` cleans it up.
- **GitHub Actions JavaScript actions opt-in to Node.js 24** via
  `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true`, ahead of the June 2, 2026
  forced migration and Node 20 runner removal on September 16, 2026
  (PR #5).
- **README Authentication section rewritten** to rank the three
  mTLS strategies by security with provisioning examples for each.

### Fixed

- **`ConfigService.GetRegistryValue` silently dropped REG_DWORD /
  REG_QWORD values.** The method read raw values with
  `key?.GetValue(name) as string`, which returns null for any
  non-string registry type. Every CSP-deployed boolean or integer
  policy using the standard DWORD wire format was silently ignored,
  breaking `GetUseMtls`, `GetAutoRotate`, `GetSkipCertCheck`,
  `GetCleanupOldProtectors`, `GetKeyEscrowIntervalHours`, and
  `GetValidateKey` for any Intune deployment that didn't explicitly
  use string values. Factored out `ConvertToConfigString` as an
  internal pure helper handling `REG_SZ`, `REG_DWORD`, and `REG_QWORD`
  consistently. Closes [#4](https://github.com/windowsadmins/crypt-escrow/issues/4).
  (PR #6)

### Credits

Huge thanks to [@aysiu](https://github.com/aysiu) for contributing the
PEM client certificate authentication path in
[#2](https://github.com/windowsadmins/crypt-escrow/pull/2). The PFX +
Credential Manager strategy and the refactor to unify the three
strategies behind a single priority-ordered dispatch were layered on
top as maintainer tweaks; aysiu is credited as co-author on the squash
merge.

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

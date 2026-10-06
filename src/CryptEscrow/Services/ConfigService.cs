using System.Runtime.Versioning;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using Serilog;
using Microsoft.Win32;

namespace CryptEscrow.Services;

/// <summary>Where an effective setting came from.</summary>
public enum SettingSource
{
    Default,
    LegacyFile,
    Environment,
    MachineSettings,
    Policy,
    CommandLine
}

/// <summary>An effective setting and the layer that supplied it.</summary>
public readonly record struct Resolved<T>(T Value, SettingSource Source);

/// <summary>
/// Resolves every setting through one chain, highest first:
/// <list type="number">
///   <item>An explicit command-line flag for this run.</item>
///   <item>Policy: <c>HKLM\SOFTWARE\Policies\Crypt\ManagedEncryption</c>, then the Intune
///   PolicyManager path <c>Crypt~Policy~ManagedEncryption</c>.</item>
///   <item>Machine settings: <c>HKLM\SOFTWARE\Crypt\ManagedEncryption\Settings</c> (64-bit
///   view), then the matching <c>CRYPT_*</c> environment variable.</item>
///   <item>The legacy <c>C:\ProgramData\ManagedEncryption\config.yaml</c>, only while no
///   one but SYSTEM and Administrators could have written it.</item>
///   <item>The built-in default.</item>
/// </list>
/// Environment variables never beat policy or the settings key.
/// </summary>
[SupportedOSPlatform("windows")]
public class ConfigService
{
    private static readonly string DefaultConfigDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "ManagedEncryption");

    private static readonly string DefaultConfigPath = Path.Combine(DefaultConfigDir, "config.yaml");
    private static readonly string DefaultMarkerPath = Path.Combine(DefaultConfigDir, "escrow.marker");

    // Test seam: when set to a non-empty absolute path, overrides the config file
    // location (and derives the marker path alongside it). Null, empty, whitespace,
    // or paths that don't resolve to a directory are treated as "not set" and the
    // defaults are used. Never set in production code.
    internal static string? ConfigPathOverride { get; set; }

    private static string? ResolvedOverrideDir =>
        !string.IsNullOrWhiteSpace(ConfigPathOverride) &&
        !string.IsNullOrWhiteSpace(Path.GetDirectoryName(ConfigPathOverride))
            ? Path.GetDirectoryName(ConfigPathOverride)
            : null;

    private static string ConfigDir => ResolvedOverrideDir ?? DefaultConfigDir;

    /// <summary>ProgramData\ManagedEncryption, where the config file and state files live.</summary>
    internal static string DataDirectory => ConfigDir;

    private static string ConfigPath =>
        ResolvedOverrideDir is null ? DefaultConfigPath : ConfigPathOverride!;

    private static string MarkerPath =>
        ResolvedOverrideDir is { } dir ? Path.Combine(dir, "escrow.marker") : DefaultMarkerPath;

    private static string TimestampPath => Path.Combine(ConfigDir, "last_escrow.txt");

    // Policy paths. Intune already targets both, so they stay as they are.
    internal const string PolicyKeyPath = @"SOFTWARE\Policies\Crypt\ManagedEncryption";
    internal const string PolicyKeyPathMdm = @"SOFTWARE\Microsoft\PolicyManager\current\device\Crypt~Policy~ManagedEncryption";

    /// <summary>The tool's own machine settings, written by <c>checkin config set</c>.</summary>
    internal const string SettingsKeyPath = @"SOFTWARE\Crypt\ManagedEncryption\Settings";

    // Test seams: when non-null, policy and settings reads and writes go through these
    // instead of HKLM, so tests can isolate under HKCU without admin. Production code
    // leaves them null.
    internal static Func<string, string?>? PolicyReaderOverride { get; set; }
    internal static Func<string, string?>? SettingsReaderOverride { get; set; }
    internal static Action<string, string>? SettingsWriterOverride { get; set; }

    // Test seam: replaces the ACL check on files under ProgramData. Returns null when
    // the file is trusted, otherwise the reason it is not.
    internal static Func<string, string?>? FileTrustOverride { get; set; }

    private static readonly IDeserializer YamlDeserializer = new DeserializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    private static readonly object NotesLock = new();
    private static readonly List<string> IgnoredFileNotesList = new();

    /// <summary>
    /// One line per file this process ignored because a non-administrator could have
    /// written it. Program logs these again once the file log is open.
    /// </summary>
    public static IReadOnlyList<string> IgnoredFileNotes
    {
        get { lock (NotesLock) return IgnoredFileNotesList.ToArray(); }
    }

    /// <summary>
    /// While true, an ignored file is recorded but not logged. Program sets it while
    /// only the console log exists, then logs <see cref="IgnoredFileNotes"/> itself.
    /// </summary>
    internal static bool DeferIgnoredFileWarnings { get; set; }

    internal static void ClearIgnoredFileNotes()
    {
        lock (NotesLock) IgnoredFileNotesList.Clear();
    }

    /// <summary>
    /// Reads a policy value: the Group Policy path, then the Intune PolicyManager path.
    /// Supports <c>REG_SZ</c>, <c>REG_DWORD</c> and <c>REG_QWORD</c>; returns <c>null</c>
    /// when the value is absent or of another type.
    /// </summary>
    internal static string? GetPolicyValue(string valueName)
    {
        if (PolicyReaderOverride is { } reader)
            return reader(valueName);

        return ReadMachineValue(PolicyKeyPath, valueName, "policy")
            ?? ReadMachineValue(PolicyKeyPathMdm, valueName, "MDM policy");
    }

    /// <summary>Reads a value from the machine settings key.</summary>
    internal static string? GetSettingsValue(string valueName)
    {
        if (SettingsReaderOverride is { } reader)
            return reader(valueName);

        return ReadMachineValue(SettingsKeyPath, valueName, "machine settings");
    }

    private static string? ReadMachineValue(string path, string valueName, string layer)
    {
        try
        {
            // The 64-bit view always, so a 32-bit host never reads WOW6432Node instead.
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(path);
            var stringValue = ConvertToConfigString(key?.GetValue(valueName));
            if (stringValue != null)
            {
                Log.Debug("Found {ValueName} in {Layer}", valueName, layer);
            }
            return stringValue;
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "Failed to read {ValueName} from {Layer}", valueName, layer);
            return null;
        }
    }

    /// <summary>
    /// Converts a raw registry value to its string form.
    /// <list type="bullet">
    ///   <item><c>REG_SZ</c> / <c>REG_EXPAND_SZ</c> (<see cref="string"/>) — returned as-is, unless null/whitespace.</item>
    ///   <item><c>REG_DWORD</c> (<see cref="int"/>) — formatted with invariant culture.</item>
    ///   <item><c>REG_QWORD</c> (<see cref="long"/>) — formatted with invariant culture.</item>
    ///   <item>Any other type (<c>REG_BINARY</c>, <c>REG_MULTI_SZ</c>, etc.) — returns null.</item>
    /// </list>
    /// </summary>
    /// <remarks>
    /// The casting bug this replaced silently dropped <c>REG_DWORD</c> values because
    /// <c>as string</c> returned null for boxed <see cref="int"/>.
    /// </remarks>
    internal static string? ConvertToConfigString(object? raw) => raw switch
    {
        null => null,
        string s when !string.IsNullOrWhiteSpace(s) => s,
        string => null, // empty or whitespace-only string treated as unset
        int i => i.ToString(System.Globalization.CultureInfo.InvariantCulture),
        long l => l.ToString(System.Globalization.CultureInfo.InvariantCulture),
        _ => null, // REG_BINARY, REG_MULTI_SZ, etc. — not supported as config values
    };

    internal static bool? ParseBool(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        if (bool.TryParse(value, out var b))
            return b;
        // Registry DWORD form: 0 = false, anything else = true.
        if (int.TryParse(value, out var i))
            return i != 0;
        return null;
    }

    internal static int? ParseInt(string? value) =>
        int.TryParse(value, out var i) ? i : null;

    /// <summary>The raw value from each layer above the legacy file, highest first.</summary>
    private static IEnumerable<(SettingSource Source, string? Raw)> MachineLayers(string valueName, string? envVar)
    {
        yield return (SettingSource.Policy, GetPolicyValue(valueName));
        yield return (SettingSource.MachineSettings, GetSettingsValue(valueName));
        if (envVar is not null)
            yield return (SettingSource.Environment, Environment.GetEnvironmentVariable(envVar));
    }

    internal static Resolved<string?> ResolveString(
        string valueName, string? envVar, Func<CryptEscrowConfig, string?> fromFile,
        string? cliValue = null, string? defaultValue = null)
    {
        if (!string.IsNullOrWhiteSpace(cliValue))
            return new(cliValue, SettingSource.CommandLine);

        foreach (var (source, raw) in MachineLayers(valueName, envVar))
        {
            if (!string.IsNullOrWhiteSpace(raw))
                return new(raw, source);
        }

        var fileValue = LoadConfig() is { } config ? fromFile(config) : null;
        if (!string.IsNullOrWhiteSpace(fileValue))
            return new(fileValue, SettingSource.LegacyFile);

        return new(defaultValue, SettingSource.Default);
    }

    internal static Resolved<bool> ResolveBool(
        string valueName, string? envVar, Func<CryptEscrowConfig, bool?> fromFile,
        bool defaultValue, bool? cliValue = null)
    {
        if (cliValue.HasValue)
            return new(cliValue.Value, SettingSource.CommandLine);

        foreach (var (source, raw) in MachineLayers(valueName, envVar))
        {
            if (ParseBool(raw) is { } value)
                return new(value, source);
        }

        if (LoadConfig() is { } config && fromFile(config) is { } fileValue)
            return new(fileValue, SettingSource.LegacyFile);

        return new(defaultValue, SettingSource.Default);
    }

    internal static Resolved<int> ResolveInt(
        string valueName, string? envVar, Func<CryptEscrowConfig, int?> fromFile, int defaultValue)
    {
        foreach (var (source, raw) in MachineLayers(valueName, envVar))
        {
            if (ParseInt(raw) is { } value)
                return new(value, source);
        }

        if (LoadConfig() is { } config && fromFile(config) is { } fileValue)
            return new(fileValue, SettingSource.LegacyFile);

        return new(defaultValue, SettingSource.Default);
    }

    // ----------------------------------------------------------------- settings

    /// <summary>The Crypt Server URL.</summary>
    public static Resolved<string?> ResolveServerUrl(string? cliOverride = null) =>
        ResolveString("ServerUrl", "CRYPT_ESCROW_SERVER_URL", c => c.Server?.Url, cliOverride);

    public static string? GetServerUrl(string? cliOverride = null) => ResolveServerUrl(cliOverride).Value;

    /// <summary>
    /// Whether to skip TLS verification. <c>--skip-cert-check</c> can only turn
    /// verification off for one run; without it the configured value applies.
    /// </summary>
    public static Resolved<bool> ResolveSkipCertCheck(bool cliOverride = false) =>
        ResolveBool("SkipCertCheck", "CRYPT_ESCROW_SKIP_CERT_CHECK",
            c => c.Server is { } s ? !s.VerifySsl : null,
            defaultValue: false, cliValue: cliOverride ? true : null);

    public static bool GetSkipCertCheck(bool cliOverride = false) => ResolveSkipCertCheck(cliOverride).Value;

    public static Resolved<bool> ResolveAutoRotate() =>
        ResolveBool("AutoRotate", "CRYPT_ESCROW_AUTO_ROTATE", c => c.Escrow?.AutoRotate, defaultValue: true);

    public static bool GetAutoRotate() => ResolveAutoRotate().Value;

    public static Resolved<bool> ResolveCleanupOldProtectors() =>
        ResolveBool("CleanupOldProtectors", "CRYPT_ESCROW_CLEANUP_OLD_PROTECTORS",
            c => c.Escrow?.CleanupOldProtectors, defaultValue: true);

    public static bool GetCleanupOldProtectors() => ResolveCleanupOldProtectors().Value;

    /// <summary>The key escrow interval in hours (inspired by Mac Crypt).</summary>
    public static Resolved<int> ResolveKeyEscrowIntervalHours() =>
        ResolveInt("KeyEscrowIntervalHours", "CRYPT_KEY_ESCROW_INTERVAL",
            c => c.Escrow?.KeyEscrowIntervalHours, defaultValue: 1);

    public static int GetKeyEscrowIntervalHours() => ResolveKeyEscrowIntervalHours().Value;

    /// <summary>Whether to validate the key locally (inspired by Mac Crypt).</summary>
    public static Resolved<bool> ResolveValidateKey() =>
        ResolveBool("ValidateKey", "CRYPT_VALIDATE_KEY", c => c.Escrow?.ValidateKey, defaultValue: true);

    public static bool GetValidateKey() => ResolveValidateKey().Value;

    /// <summary>Users to skip from escrow enforcement, comma-separated (inspired by Mac Crypt).</summary>
    public static Resolved<string?> ResolveSkipUsers() =>
        ResolveString("SkipUsers", "CRYPT_SKIP_USERS",
            c => c.Escrow?.SkipUsers is { Length: > 0 } users ? string.Join(",", users) : null);

    public static string[]? GetSkipUsers() =>
        ResolveSkipUsers().Value?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>Command to run after error conditions (inspired by Mac Crypt).</summary>
    public static Resolved<string?> ResolvePostRunCommand() =>
        ResolveString("PostRunCommand", "CRYPT_POST_RUN_COMMAND", c => c.Escrow?.PostRunCommand);

    public static string? GetPostRunCommand() => ResolvePostRunCommand().Value;

    /// <summary>The API key for server authentication.</summary>
    /// <summary>
    /// The API key. Policy and machine settings hold it only until an elevated run moves
    /// it into <see cref="SecretStore"/>, which then supplies it; the environment and
    /// config.yaml follow, for runs that have not migrated yet.
    /// </summary>
    public static Resolved<string?> ResolveApiKey()
    {
        if (GetPolicyValue("ApiKey") is { } policy)
            return new(policy, SettingSource.Policy);
        if (GetSettingsValue("ApiKey") is { } settings)
            return new(settings, SettingSource.MachineSettings);
        if (SecretStore.Read("ApiKey") is { } stored)
            return new(stored, SecretStore.ReadSource("ApiKey") ?? SettingSource.MachineSettings);
        if (Environment.GetEnvironmentVariable("CRYPT_API_KEY") is { Length: > 0 } env)
            return new(env, SettingSource.Environment);
        var file = LoadConfig()?.Server?.Auth?.ApiKey;
        return string.IsNullOrWhiteSpace(file)
            ? new(null, SettingSource.Default)
            : new(file, SettingSource.LegacyFile);
    }

    public static string? GetApiKey() => ResolveApiKey().Value;

    public static Resolved<string?> ResolveApiKeyHeader() =>
        ResolveString("ApiKeyHeader", "CRYPT_API_KEY_HEADER", c => c.Server?.Auth?.ApiKeyHeader,
            defaultValue: "X-API-Key");

    public static string GetApiKeyHeader() => ResolveApiKeyHeader().Value!;

    public static Resolved<bool> ResolveUseMtls() =>
        ResolveBool("UseMtls", "CRYPT_USE_MTLS", c => c.Server?.Auth?.UseMtls, defaultValue: false);

    public static bool GetUseMtls() => ResolveUseMtls().Value;

    public static Resolved<string?> ResolveCertificateSubject() =>
        ResolveString("CertificateSubject", "CRYPT_CERT_SUBJECT", c => c.Server?.Auth?.CertificateSubject);

    public static string? GetCertificateSubject() => ResolveCertificateSubject().Value;

    public static Resolved<string?> ResolveCertificateThumbprint() =>
        ResolveString("CertificateThumbprint", "CRYPT_CERT_THUMBPRINT", c => c.Server?.Auth?.CertificateThumbprint);

    public static string? GetCertificateThumbprint() => ResolveCertificateThumbprint().Value;

    public static Resolved<string?> ResolveCertificateStoreLocation() =>
        ResolveString("CertificateStoreLocation", "CRYPT_CERT_STORE_LOCATION",
            c => c.Server?.Auth?.CertificateStoreLocation, defaultValue: "LocalMachine");

    public static Resolved<string?> ResolveCertificateStoreName() =>
        ResolveString("CertificateStoreName", "CRYPT_CERT_STORE_NAME",
            c => c.Server?.Auth?.CertificateStoreName, defaultValue: "My");

    /// <summary>Path to a client certificate PEM file for mTLS.</summary>
    public static Resolved<string?> ResolveClientCertPath() =>
        ResolveString("ClientCertPath", "CRYPT_CLIENT_CERT_PATH", c => c.Server?.Auth?.ClientCertPath);

    public static string? GetClientCertPath() => ResolveClientCertPath().Value;

    /// <summary>Path to the client private key PEM file for mTLS (paired with ClientCertPath).</summary>
    public static Resolved<string?> ResolveClientKeyPath() =>
        ResolveString("ClientKeyPath", "CRYPT_CLIENT_KEY_PATH", c => c.Server?.Auth?.ClientKeyPath);

    public static string? GetClientKeyPath() => ResolveClientKeyPath().Value;

    /// <summary>
    /// Path to a client certificate PFX file for mTLS. Preferred over PEM because the
    /// private key is encrypted at rest and the passphrase is pulled from Credential Manager.
    /// </summary>
    public static Resolved<string?> ResolvePfxPath() =>
        ResolveString("PfxPath", "CRYPT_PFX_PATH", c => c.Server?.Auth?.PfxPath);

    public static string? GetPfxPath() => ResolvePfxPath().Value;

    /// <summary>Name of the Windows Credential Manager entry holding the PFX passphrase.</summary>
    public static Resolved<string?> ResolvePfxPasswordCredential() =>
        ResolveString("PfxPasswordCredential", "CRYPT_PFX_PASSWORD_CRED", c => c.Server?.Auth?.PfxPasswordCredential);

    public static string? GetPfxPasswordCredential() => ResolvePfxPasswordCredential().Value;

    public static Resolved<string?> ResolveLogLevel() =>
        ResolveString("LogLevel", "CRYPT_LOG_LEVEL", c => c.Logging?.Level, defaultValue: "INFO");

    public static Resolved<string?> ResolveLogFilePath() =>
        ResolveString("LogFilePath", "CRYPT_LOG_FILE_PATH", c => c.Logging?.FilePath);

    public static Resolved<int> ResolveLogRetainedDays() =>
        ResolveInt("LogRetainedDays", "CRYPT_LOG_RETAINED_DAYS", c => c.Logging?.RetainedDays, defaultValue: 30);

    /// <summary>The effective logging settings, from every layer.</summary>
    public static LoggingConfig GetLoggingConfig() => new()
    {
        Level = ResolveLogLevel().Value!,
        FilePath = ResolveLogFilePath().Value,
        RetainedDays = ResolveLogRetainedDays().Value
    };

    /// <summary>
    /// Gets the full authentication configuration.
    /// </summary>
    public static AuthConfig GetAuthConfig() => new()
    {
        ApiKey = GetApiKey(),
        ApiKeyHeader = GetApiKeyHeader(),
        UseMtls = GetUseMtls(),
        CertificateSubject = GetCertificateSubject(),
        CertificateThumbprint = GetCertificateThumbprint(),
        CertificateStoreLocation = ResolveCertificateStoreLocation().Value!,
        CertificateStoreName = ResolveCertificateStoreName().Value!,
        ClientCertPath = GetClientCertPath(),
        ClientKeyPath = GetClientKeyPath(),
        PfxPath = GetPfxPath(),
        PfxPasswordCredential = GetPfxPasswordCredential()
    };

    /// <summary>
    /// Every setting with its effective value and the layer it came from, for
    /// <c>config show</c>. The API key is masked.
    /// </summary>
    public static IReadOnlyList<(string Name, string Value, SettingSource Source)> Describe()
    {
        static (string, string, SettingSource) S(string name, Resolved<string?> r) =>
            (name, r.Value ?? "(not set)", r.Source);
        static (string, string, SettingSource) B(string name, Resolved<bool> r) =>
            (name, r.Value ? "true" : "false", r.Source);
        static (string, string, SettingSource) I(string name, Resolved<int> r) =>
            (name, r.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), r.Source);

        var apiKey = ResolveApiKey();
        return
        [
            S("ServerUrl", ResolveServerUrl()),
            B("SkipCertCheck", ResolveSkipCertCheck()),
            B("AutoRotate", ResolveAutoRotate()),
            B("CleanupOldProtectors", ResolveCleanupOldProtectors()),
            I("KeyEscrowIntervalHours", ResolveKeyEscrowIntervalHours()),
            B("ValidateKey", ResolveValidateKey()),
            S("SkipUsers", ResolveSkipUsers()),
            S("PostRunCommand", ResolvePostRunCommand()),
            ("ApiKey", apiKey.Value is null ? "(not set)" : "(set)", apiKey.Source),
            S("ApiKeyHeader", ResolveApiKeyHeader()),
            B("UseMtls", ResolveUseMtls()),
            S("CertificateSubject", ResolveCertificateSubject()),
            S("CertificateThumbprint", ResolveCertificateThumbprint()),
            S("CertificateStoreLocation", ResolveCertificateStoreLocation()),
            S("CertificateStoreName", ResolveCertificateStoreName()),
            S("ClientCertPath", ResolveClientCertPath()),
            S("ClientKeyPath", ResolveClientKeyPath()),
            S("PfxPath", ResolvePfxPath()),
            S("PfxPasswordCredential", ResolvePfxPasswordCredential()),
            S("LogLevel", ResolveLogLevel()),
            S("LogFilePath", ResolveLogFilePath()),
            I("LogRetainedDays", ResolveLogRetainedDays()),
        ];
    }

    // -------------------------------------------------------------- legacy file

    /// <summary>
    /// Null when <paramref name="path"/> may be trusted. Otherwise records why in
    /// <see cref="IgnoredFileNotes"/>, logs it the first time, and returns it.
    /// </summary>
    private static string? CheckTrusted(string path, string what, bool log = true)
    {
        var reason = FileTrustOverride is { } check ? check(path) : TrustedFile.WhyUntrusted(path);
        if (reason is null)
            return null;

        var note = $"Ignoring {what}: {reason}";
        bool first;
        lock (NotesLock)
        {
            first = !IgnoredFileNotesList.Contains(note);
            if (first) IgnoredFileNotesList.Add(note);
        }
        if (first && log && !DeferIgnoredFileWarnings)
            Log.Warning("{Note}", note);
        return reason;
    }

    /// <summary>
    /// Loads the legacy YAML file. Returns null when it is absent, unreadable, or could
    /// have been written by an account other than SYSTEM and Administrators.
    /// </summary>
    public static CryptEscrowConfig? LoadConfig()
    {
        if (!File.Exists(ConfigPath))
            return null;

        if (CheckTrusted(ConfigPath, "config file") is not null)
            return null;

        try
        {
            var yaml = File.ReadAllText(ConfigPath);
            return YamlDeserializer.Deserialize<CryptEscrowConfig>(yaml);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to load config from {Path}", ConfigPath);
            return null;
        }
    }

    // --------------------------------------------------------- machine settings

    /// <summary>
    /// <c>config set</c> keys and the settings value each one writes. The value names
    /// themselves are accepted as keys too.
    /// </summary>
    internal static readonly IReadOnlyDictionary<string, string> SettableKeys =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["server.url"] = "ServerUrl",
            ["server.skip_cert_check"] = "SkipCertCheck",
            ["escrow.auto_rotate"] = "AutoRotate",
            ["escrow.cleanup_old_protectors"] = "CleanupOldProtectors",
            ["escrow.key_escrow_interval_hours"] = "KeyEscrowIntervalHours",
            ["escrow.validate_key"] = "ValidateKey",
            ["escrow.skip_users"] = "SkipUsers",
            ["escrow.post_run_command"] = "PostRunCommand",
            ["server.auth.api_key"] = "ApiKey",
            ["server.auth.api_key_header"] = "ApiKeyHeader",
            ["server.auth.use_mtls"] = "UseMtls",
            ["server.auth.certificate_subject"] = "CertificateSubject",
            ["server.auth.certificate_thumbprint"] = "CertificateThumbprint",
            ["server.auth.certificate_store_location"] = "CertificateStoreLocation",
            ["server.auth.certificate_store_name"] = "CertificateStoreName",
            ["server.auth.client_cert_path"] = "ClientCertPath",
            ["server.auth.client_key_path"] = "ClientKeyPath",
            ["server.auth.pfx_path"] = "PfxPath",
            ["server.auth.pfx_password_credential"] = "PfxPasswordCredential",
            ["logging.level"] = "LogLevel",
            ["logging.file_path"] = "LogFilePath",
            ["logging.retained_days"] = "LogRetainedDays",
        };

    private static readonly HashSet<string> BoolSettings = new(StringComparer.OrdinalIgnoreCase)
    {
        "SkipCertCheck", "AutoRotate", "CleanupOldProtectors", "ValidateKey", "UseMtls"
    };

    private static readonly HashSet<string> IntSettings = new(StringComparer.OrdinalIgnoreCase)
    {
        "KeyEscrowIntervalHours", "LogRetainedDays"
    };

    /// <summary>
    /// Writes one setting to <c>HKLM\SOFTWARE\Crypt\ManagedEncryption\Settings</c>, which
    /// needs an elevated process. <c>server.verify_ssl</c> is still accepted and stored
    /// as the inverse <c>SkipCertCheck</c>.
    /// </summary>
    public static void SetValue(string key, string value)
    {
        string valueName;
        if (string.Equals(key, "server.verify_ssl", StringComparison.OrdinalIgnoreCase))
        {
            valueName = "SkipCertCheck";
            value = (!(ParseBool(value) ?? throw new ArgumentException($"Not a boolean: {value}"))).ToString();
        }
        else if (SettableKeys.TryGetValue(key, out var mapped))
        {
            valueName = mapped;
        }
        else if (SettableKeys.Values.FirstOrDefault(v => string.Equals(v, key, StringComparison.OrdinalIgnoreCase)) is { } name)
        {
            valueName = name;
        }
        else
        {
            throw new ArgumentException($"Unknown configuration key: {key}");
        }

        // Credentials go to the protected store, never to the user-readable settings key.
        if (SecretStore.IsSecret(valueName))
        {
            if (SecretStore.IsSetByPolicy(valueName))
                throw new InvalidOperationException($"{valueName} is managed by policy");
            SecretStore.Write(valueName, value);
            Log.Information("Saved {ValueName} to the protected store", valueName);
            return;
        }

        if (BoolSettings.Contains(valueName))
            value = (ParseBool(value) ?? throw new ArgumentException($"Not a boolean: {value}")).ToString();
        value = value.ToLowerInvariant() is "true" or "false" ? value.ToLowerInvariant() : value;
        if (IntSettings.Contains(valueName) && ParseInt(value) is null)
            throw new ArgumentException($"Not a whole number: {value}");

        if (SettingsWriterOverride is { } writer)
        {
            writer(valueName, value);
        }
        else
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var settings = baseKey.CreateSubKey(SettingsKeyPath, writable: true);
            settings.SetValue(valueName, value, RegistryValueKind.String);
            Log.Information("Set {ValueName} in HKLM\\{Path}", valueName, SettingsKeyPath);
        }

        if (GetPolicyValue(valueName) is not null)
            Log.Warning("{ValueName} is also set by policy, and policy takes precedence", valueName);
    }

    // -------------------------------------------------------------- state files

    /// <summary>
    /// Gets the last escrowed protector ID from marker file.
    /// </summary>
    public static string? GetLastEscrowedProtectorId()
    {
        if (!File.Exists(MarkerPath) || CheckTrusted(MarkerPath, "escrow marker") is not null)
            return null;

        try
        {
            return File.ReadAllText(MarkerPath).Trim();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Saves the escrowed protector ID to marker file.
    /// </summary>
    public static void SaveEscrowedProtectorId(string protectorId)
    {
        WriteStateFile(MarkerPath, protectorId);
        SaveLastEscrowTimestamp();
    }

    /// <summary>
    /// Saves the current timestamp as the last successful escrow time.
    /// </summary>
    public static void SaveLastEscrowTimestamp()
    {
        WriteStateFile(TimestampPath, DateTimeOffset.UtcNow.ToString("o"));
    }

    /// <summary>
    /// Writes a state file, first removing one that is not trusted: writing into it
    /// would keep its owner and permissions, so it would never be trusted afterwards.
    /// </summary>
    private static void WriteStateFile(string path, string content)
    {
        Directory.CreateDirectory(ConfigDir);
        if (File.Exists(path) && CheckTrusted(path, "state file", log: false) is { } reason)
        {
            File.Delete(path);
            Log.Warning("Replaced {Path}: {Reason}", path, reason);
        }
        File.WriteAllText(path, content);
    }

    /// <summary>
    /// Gets the last escrow timestamp, or null if never escrowed.
    /// </summary>
    public static DateTimeOffset? GetLastEscrowTimestamp()
    {
        if (!File.Exists(TimestampPath) || CheckTrusted(TimestampPath, "last escrow timestamp") is not null)
            return null;

        try
        {
            var content = File.ReadAllText(TimestampPath);
            return DateTimeOffset.Parse(content);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to read last escrow timestamp");
            return null;
        }
    }

    /// <summary>
    /// Checks if enough time has elapsed since the last escrow based on the configured interval.
    /// </summary>
    /// <returns>True if escrow should proceed, false if still within the interval window.</returns>
    public static bool ShouldEscrowNow()
    {
        var lastEscrow = GetLastEscrowTimestamp();
        if (!lastEscrow.HasValue)
            return true; // Never escrowed before

        var intervalHours = GetKeyEscrowIntervalHours();
        var nextEscrowTime = lastEscrow.Value.AddHours(intervalHours);
        var now = DateTimeOffset.UtcNow;

        return now >= nextEscrowTime;
    }

    public static string GetConfigPath() => ConfigPath;
}

public class CryptEscrowConfig
{
    public ServerConfig? Server { get; set; }
    public EscrowConfig? Escrow { get; set; }
    public LoggingConfig? Logging { get; set; }
}

public class ServerConfig
{
    public string? Url { get; set; }
    public bool VerifySsl { get; set; } = true;
    public int TimeoutSeconds { get; set; } = 30;
    public int RetryAttempts { get; set; } = 3;
    
    /// <summary>
    /// Authentication configuration for server communication.
    /// </summary>
    public AuthConfig? Auth { get; set; }
}

/// <summary>
/// Authentication configuration supporting API key and mTLS.
/// </summary>
public class AuthConfig
{
    /// <summary>
    /// API key/token for server authentication.
    /// Can also be set via CRYPT_API_KEY environment variable.
    /// </summary>
    public string? ApiKey { get; set; }
    
    /// <summary>
    /// Custom header name for API key (default: X-API-Key).
    /// </summary>
    public string ApiKeyHeader { get; set; } = "X-API-Key";
    
    /// <summary>
    /// Enable mutual TLS (mTLS) authentication using client certificate.
    /// </summary>
    public bool UseMtls { get; set; } = false;
    
    /// <summary>
    /// Certificate subject name (CN) to find in Windows Certificate Store.
    /// Similar to Mac Crypt's CommonNameForEscrow.
    /// </summary>
    public string? CertificateSubject { get; set; }
    
    /// <summary>
    /// Certificate thumbprint to find in Windows Certificate Store.
    /// Alternative to CertificateSubject for more precise certificate selection.
    /// </summary>
    public string? CertificateThumbprint { get; set; }
    
    /// <summary>
    /// Certificate store location (CurrentUser or LocalMachine).
    /// Default: LocalMachine for system-wide certificates.
    /// </summary>
    public string CertificateStoreLocation { get; set; } = "LocalMachine";
    
    /// <summary>
    /// Certificate store name (My, Root, etc.).
    /// Default: My (Personal certificates).
    /// </summary>
    public string CertificateStoreName { get; set; } = "My";

    /// <summary>
    /// Path to a client certificate PEM file for mTLS. Least preferred file-based option
    /// because the paired private key sits in plaintext on disk. Must be used together
    /// with <see cref="ClientKeyPath"/>.
    /// </summary>
    public string? ClientCertPath { get; set; }

    /// <summary>
    /// Path to the client private key PEM file for mTLS. Paired with <see cref="ClientCertPath"/>.
    /// Lock this file down with a restrictive ACL — the key is unencrypted at rest.
    /// </summary>
    public string? ClientKeyPath { get; set; }

    /// <summary>
    /// Path to a client certificate PFX (PKCS#12) file for mTLS. Preferred file-based option
    /// because the private key is encrypted at rest. The decryption passphrase is read from
    /// Windows Credential Manager via <see cref="PfxPasswordCredential"/>.
    /// </summary>
    public string? PfxPath { get; set; }

    /// <summary>
    /// Name of a generic Windows Credential Manager entry whose password blob holds the PFX
    /// passphrase. The password is never stored in YAML, environment variables, or the registry.
    /// Provision with <c>cmdkey /generic:&lt;name&gt; /user:&lt;anything&gt; /pass:&lt;secret&gt;</c>.
    /// </summary>
    public string? PfxPasswordCredential { get; set; }
}

public class EscrowConfig
{
    public string SecretType { get; set; } = "recovery_key";
    public bool AutoRotate { get; set; } = true;
    public bool CleanupOldProtectors { get; set; } = true;
    
    // Inspired by Mac Crypt client
    public int KeyEscrowIntervalHours { get; set; } = 1;
    public bool ValidateKey { get; set; } = true;
    public string? PostRunCommand { get; set; }
    public string[]? SkipUsers { get; set; }
}

public class LoggingConfig
{
    /// <summary>Minimum level to record. Unrecognised values fall back to Information.</summary>
    public string Level { get; set; } = "INFO";

    /// <summary>
    /// Where to write the log. Bound from "file_path", which is the key the installer
    /// writes -- the property was called Path, so the key never bound to anything and
    /// the setting was silently ignored.
    /// </summary>
    public string? FilePath { get; set; }

    /// <summary>Days of rolled log files to keep.</summary>
    public int RetainedDays { get; set; } = 30;
}

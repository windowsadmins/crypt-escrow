using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using Serilog;
using Microsoft.Win32;

namespace CryptEscrow.Services;

/// <summary>
/// Configuration service with registry (CSP/OMA-URI), YAML file, and environment variable support.
/// </summary>
public class ConfigService
{
    private static readonly string ConfigDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "ManagedEncryption");
    
    private static readonly string ConfigPath = Path.Combine(ConfigDir, "config.yaml");
    private static readonly string MarkerPath = Path.Combine(ConfigDir, "escrow.marker");

    // CSP/OMA-URI registry paths for enterprise policy
    private const string RegistryBasePath = @"SOFTWARE\Policies\Crypt\ManagedEncryption";
    private const string RegistryBasePathMdm = @"SOFTWARE\Microsoft\PolicyManager\current\device\Crypt~Policy~ManagedEncryption";

    private static readonly IDeserializer YamlDeserializer = new DeserializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    private static readonly ISerializer YamlSerializer = new SerializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .Build();

    /// <summary>
    /// Reads a string value from the enterprise policy registry (CSP/OMA-URI).
    /// Checks both standard Policies path and MDM PolicyManager path.
    /// </summary>
    private static string? GetRegistryValue(string valueName)
    {
        try
        {
            // Try standard Group Policy path first
            using var key = Registry.LocalMachine.OpenSubKey(RegistryBasePath);
            var value = key?.GetValue(valueName) as string;
            if (!string.IsNullOrWhiteSpace(value))
            {
                Log.Debug("Found registry value {ValueName} in GP path", valueName);
                return value;
            }
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "Failed to read registry value {ValueName} from GP path", valueName);
        }

        try
        {
            // Try MDM (Intune) PolicyManager path
            using var key = Registry.LocalMachine.OpenSubKey(RegistryBasePathMdm);
            var value = key?.GetValue(valueName) as string;
            if (!string.IsNullOrWhiteSpace(value))
            {
                Log.Debug("Found registry value {ValueName} in MDM path", valueName);
                return value;
            }
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "Failed to read registry value {ValueName} from MDM path", valueName);
        }

        return null;
    }

    /// <summary>
    /// Reads a boolean value from the enterprise policy registry.
    /// </summary>
    private static bool? GetRegistryBool(string valueName)
    {
        var strValue = GetRegistryValue(valueName);
        if (string.IsNullOrWhiteSpace(strValue))
            return null;

        if (bool.TryParse(strValue, out var boolValue))
            return boolValue;

        // Handle registry DWORD values (0 = false, 1 = true)
        if (int.TryParse(strValue, out var intValue))
            return intValue != 0;

        return null;
    }

    /// <summary>
    /// Reads an integer value from the enterprise policy registry.
    /// </summary>
    private static int? GetRegistryInt(string valueName)
    {
        var strValue = GetRegistryValue(valueName);
        if (string.IsNullOrWhiteSpace(strValue))
            return null;

        return int.TryParse(strValue, out var intValue) ? intValue : null;
    }

    /// <summary>
    /// Gets the Crypt Server URL from config or environment.
    /// Priority: CLI override > Environment variable > Registry (CSP/OMA-URI) > YAML config file
    /// </summary>
    public static string? GetServerUrl(string? cliOverride = null)
    {
        // CLI override takes precedence
        if (!string.IsNullOrWhiteSpace(cliOverride))
            return cliOverride;

        // Environment variable
        var envUrl = Environment.GetEnvironmentVariable("CRYPT_ESCROW_SERVER_URL");
        if (!string.IsNullOrWhiteSpace(envUrl))
            return envUrl;

        // Enterprise registry (CSP/OMA-URI from Intune)
        var regUrl = GetRegistryValue("ServerUrl");
        if (!string.IsNullOrWhiteSpace(regUrl))
            return regUrl;

        // Config file
        var config = LoadConfig();
        return config?.Server?.Url;
    }

    /// <summary>
    /// Gets whether to skip SSL verification.
    /// Priority: CLI override > Environment variable > Registry > YAML config
    /// </summary>
    public static bool GetSkipCertCheck(bool cliOverride = false)
    {
        if (cliOverride)
            return true;

        var envValue = Environment.GetEnvironmentVariable("CRYPT_ESCROW_SKIP_CERT_CHECK");
        if (bool.TryParse(envValue, out var envBool))
            return envBool;

        var regValue = GetRegistryBool("SkipCertCheck");
        if (regValue.HasValue)
            return regValue.Value;

        var config = LoadConfig();
        return config?.Server?.VerifySsl == false;
    }

    /// <summary>
    /// Gets whether to auto-rotate keys.
    /// Priority: Environment variable > Registry > YAML config
    /// </summary>
    public static bool GetAutoRotate()
    {
        var envValue = Environment.GetEnvironmentVariable("CRYPT_ESCROW_AUTO_ROTATE");
        if (bool.TryParse(envValue, out var envBool))
            return envBool;

        var regValue = GetRegistryBool("AutoRotate");
        if (regValue.HasValue)
            return regValue.Value;

        var config = LoadConfig();
        return config?.Escrow?.AutoRotate ?? true;
    }

    /// <summary>
    /// Gets whether to cleanup old protectors.
    /// Priority: Environment variable > Registry > YAML config
    /// </summary>
    public static bool GetCleanupOldProtectors()
    {
        var envValue = Environment.GetEnvironmentVariable("CRYPT_ESCROW_CLEANUP_OLD_PROTECTORS");
        if (bool.TryParse(envValue, out var envBool))
            return envBool;

        var regValue = GetRegistryBool("CleanupOldProtectors");
        if (regValue.HasValue)
            return regValue.Value;

        var config = LoadConfig();
        return config?.Escrow?.CleanupOldProtectors ?? true;
    }

    /// <summary>
    /// Gets the key escrow interval in hours (inspired by Mac Crypt).
    /// Priority: Environment variable > Registry > YAML config
    /// </summary>
    public static int GetKeyEscrowIntervalHours()
    {
        var envValue = Environment.GetEnvironmentVariable("CRYPT_KEY_ESCROW_INTERVAL");
        if (int.TryParse(envValue, out var hours))
            return hours;

        var regValue = GetRegistryInt("KeyEscrowIntervalHours");
        if (regValue.HasValue)
            return regValue.Value;

        var config = LoadConfig();
        return config?.Escrow?.KeyEscrowIntervalHours ?? 1;
    }

    /// <summary>
    /// Gets whether to validate the key locally (inspired by Mac Crypt).
    /// Priority: Environment variable > Registry > YAML config
    /// </summary>
    public static bool GetValidateKey()
    {
        var envValue = Environment.GetEnvironmentVariable("CRYPT_VALIDATE_KEY");
        if (bool.TryParse(envValue, out var validate))
            return validate;

        var regValue = GetRegistryBool("ValidateKey");
        if (regValue.HasValue)
            return regValue.Value;

        var config = LoadConfig();
        return config?.Escrow?.ValidateKey ?? true;
    }

    /// <summary>
    /// Gets users to skip from escrow enforcement (inspired by Mac Crypt).
    /// Priority: Environment variable > Registry > YAML config
    /// </summary>
    public static string[]? GetSkipUsers()
    {
        var envValue = Environment.GetEnvironmentVariable("CRYPT_SKIP_USERS");
        if (!string.IsNullOrWhiteSpace(envValue))
            return envValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var regValue = GetRegistryValue("SkipUsers");
        if (!string.IsNullOrWhiteSpace(regValue))
            return regValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var config = LoadConfig();
        return config?.Escrow?.SkipUsers;
    }

    /// <summary>
    /// Gets command to run after error conditions (inspired by Mac Crypt).
    /// Priority: Environment variable > Registry > YAML config
    /// </summary>
    public static string? GetPostRunCommand()
    {
        var envValue = Environment.GetEnvironmentVariable("CRYPT_POST_RUN_COMMAND");
        if (!string.IsNullOrWhiteSpace(envValue))
            return envValue;

        var regValue = GetRegistryValue("PostRunCommand");
        if (!string.IsNullOrWhiteSpace(regValue))
            return regValue;

        var config = LoadConfig();
        return config?.Escrow?.PostRunCommand;
    }

    /// <summary>
    /// Gets the API key for server authentication.
    /// Priority: Environment variable > Registry > YAML config
    /// </summary>
    public static string? GetApiKey()
    {
        var envValue = Environment.GetEnvironmentVariable("CRYPT_API_KEY");
        if (!string.IsNullOrWhiteSpace(envValue))
            return envValue;

        var regValue = GetRegistryValue("ApiKey");
        if (!string.IsNullOrWhiteSpace(regValue))
            return regValue;

        var config = LoadConfig();
        return config?.Server?.Auth?.ApiKey;
    }

    /// <summary>
    /// Gets the API key header name.
    /// Priority: Environment variable > Registry > YAML config
    /// </summary>
    public static string GetApiKeyHeader()
    {
        var envValue = Environment.GetEnvironmentVariable("CRYPT_API_KEY_HEADER");
        if (!string.IsNullOrWhiteSpace(envValue))
            return envValue;

        var regValue = GetRegistryValue("ApiKeyHeader");
        if (!string.IsNullOrWhiteSpace(regValue))
            return regValue;

        var config = LoadConfig();
        return config?.Server?.Auth?.ApiKeyHeader ?? "X-API-Key";
    }

    /// <summary>
    /// Gets whether to use mTLS authentication.
    /// Priority: Environment variable > Registry > YAML config
    /// </summary>
    public static bool GetUseMtls()
    {
        var envValue = Environment.GetEnvironmentVariable("CRYPT_USE_MTLS");
        if (bool.TryParse(envValue, out var envBool))
            return envBool;

        var regValue = GetRegistryBool("UseMtls");
        if (regValue.HasValue)
            return regValue.Value;

        var config = LoadConfig();
        return config?.Server?.Auth?.UseMtls ?? false;
    }

    /// <summary>
    /// Gets the certificate subject name for mTLS.
    /// Priority: Environment variable > Registry > YAML config
    /// </summary>
    public static string? GetCertificateSubject()
    {
        var envValue = Environment.GetEnvironmentVariable("CRYPT_CERT_SUBJECT");
        if (!string.IsNullOrWhiteSpace(envValue))
            return envValue;

        var regValue = GetRegistryValue("CertificateSubject");
        if (!string.IsNullOrWhiteSpace(regValue))
            return regValue;

        var config = LoadConfig();
        return config?.Server?.Auth?.CertificateSubject;
    }

    /// <summary>
    /// Gets the certificate thumbprint for mTLS.
    /// Priority: Environment variable > Registry > YAML config
    /// </summary>
    public static string? GetCertificateThumbprint()
    {
        var envValue = Environment.GetEnvironmentVariable("CRYPT_CERT_THUMBPRINT");
        if (!string.IsNullOrWhiteSpace(envValue))
            return envValue;

        var regValue = GetRegistryValue("CertificateThumbprint");
        if (!string.IsNullOrWhiteSpace(regValue))
            return regValue;

        var config = LoadConfig();
        return config?.Server?.Auth?.CertificateThumbprint;
    }

    /// <summary>
    /// Gets the full authentication configuration.
    /// </summary>
    public static AuthConfig GetAuthConfig()
    {
        var config = LoadConfig();
        return new AuthConfig
        {
            ApiKey = GetApiKey(),
            ApiKeyHeader = GetApiKeyHeader(),
            UseMtls = GetUseMtls(),
            CertificateSubject = GetCertificateSubject(),
            CertificateThumbprint = GetCertificateThumbprint(),
            CertificateStoreLocation = config?.Server?.Auth?.CertificateStoreLocation ?? "LocalMachine",
            CertificateStoreName = config?.Server?.Auth?.CertificateStoreName ?? "My"
        };
    }

    /// <summary>
    /// Loads the configuration from YAML file.
    /// </summary>
    public static CryptEscrowConfig? LoadConfig()
    {
        if (!File.Exists(ConfigPath))
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

    /// <summary>
    /// Saves configuration to YAML file.
    /// </summary>
    public static void SaveConfig(CryptEscrowConfig config)
    {
        Directory.CreateDirectory(ConfigDir);
        var yaml = YamlSerializer.Serialize(config);
        File.WriteAllText(ConfigPath, yaml);
        Log.Information("Configuration saved to {Path}", ConfigPath);
    }

    /// <summary>
    /// Sets a configuration value by key path (e.g., "server.url").
    /// </summary>
    public static void SetValue(string key, string value)
    {
        var config = LoadConfig() ?? new CryptEscrowConfig();

        var parts = key.ToLower().Split('.');
        switch (parts)
        {
            case ["server", "url"]:
                config.Server ??= new ServerConfig();
                config.Server.Url = value;
                break;
            case ["server", "verify_ssl"]:
                config.Server ??= new ServerConfig();
                config.Server.VerifySsl = bool.Parse(value);
                break;
            case ["server", "timeout_seconds"]:
                config.Server ??= new ServerConfig();
                config.Server.TimeoutSeconds = int.Parse(value);
                break;
            case ["escrow", "auto_rotate"]:
                config.Escrow ??= new EscrowConfig();
                config.Escrow.AutoRotate = bool.Parse(value);
                break;
            case ["escrow", "cleanup_old_protectors"]:
                config.Escrow ??= new EscrowConfig();
                config.Escrow.CleanupOldProtectors = bool.Parse(value);
                break;
            default:
                throw new ArgumentException($"Unknown configuration key: {key}");
        }

        SaveConfig(config);
    }

    /// <summary>
    /// Gets the last escrowed protector ID from marker file.
    /// </summary>
    public static string? GetLastEscrowedProtectorId()
    {
        if (!File.Exists(MarkerPath))
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
        Directory.CreateDirectory(ConfigDir);
        File.WriteAllText(MarkerPath, protectorId);
        SaveLastEscrowTimestamp();
    }

    /// <summary>
    /// Saves the current timestamp as the last successful escrow time.
    /// </summary>
    public static void SaveLastEscrowTimestamp()
    {
        Directory.CreateDirectory(ConfigDir);
        var timestampPath = Path.Combine(ConfigDir, "last_escrow.txt");
        File.WriteAllText(timestampPath, DateTimeOffset.UtcNow.ToString("o"));
    }

    /// <summary>
    /// Gets the last escrow timestamp, or null if never escrowed.
    /// </summary>
    public static DateTimeOffset? GetLastEscrowTimestamp()
    {
        var timestampPath = Path.Combine(ConfigDir, "last_escrow.txt");
        if (!File.Exists(timestampPath))
            return null;

        try
        {
            var content = File.ReadAllText(timestampPath);
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
    public string Level { get; set; } = "INFO";
    public string? Path { get; set; }
    public int RetainedDays { get; set; } = 30;
}

using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using Serilog;

namespace CryptEscrow.Services;

/// <summary>
/// Configuration service with YAML file and environment variable support.
/// </summary>
public class ConfigService
{
    private static readonly string ConfigDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "CryptEscrow");
    
    private static readonly string ConfigPath = Path.Combine(ConfigDir, "config.yaml");
    private static readonly string MarkerPath = Path.Combine(ConfigDir, "escrow.marker");

    private static readonly IDeserializer YamlDeserializer = new DeserializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    private static readonly ISerializer YamlSerializer = new SerializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .Build();

    /// <summary>
    /// Gets the Crypt Server URL from config or environment.
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

        // Config file
        var config = LoadConfig();
        return config?.Server?.Url;
    }

    /// <summary>
    /// Gets whether to skip SSL verification.
    /// </summary>
    public static bool GetSkipCertCheck(bool cliOverride = false)
    {
        if (cliOverride)
            return true;

        var envValue = Environment.GetEnvironmentVariable("CRYPT_ESCROW_SKIP_CERT_CHECK");
        if (bool.TryParse(envValue, out var envBool))
            return envBool;

        var config = LoadConfig();
        return config?.Server?.VerifySsl == false;
    }

    /// <summary>
    /// Gets whether to auto-rotate keys.
    /// </summary>
    public static bool GetAutoRotate()
    {
        var envValue = Environment.GetEnvironmentVariable("CRYPT_ESCROW_AUTO_ROTATE");
        if (bool.TryParse(envValue, out var envBool))
            return envBool;

        var config = LoadConfig();
        return config?.Escrow?.AutoRotate ?? true;
    }

    /// <summary>
    /// Gets whether to cleanup old protectors.
    /// </summary>
    public static bool GetCleanupOldProtectors()
    {
        var envValue = Environment.GetEnvironmentVariable("CRYPT_ESCROW_CLEANUP_OLD_PROTECTORS");
        if (bool.TryParse(envValue, out var envBool))
            return envBool;

        var config = LoadConfig();
        return config?.Escrow?.CleanupOldProtectors ?? true;
    }

    /// <summary>
    /// Gets the key escrow interval in hours (inspired by Mac Crypt).
    /// </summary>
    public static int GetKeyEscrowIntervalHours()
    {
        var envValue = Environment.GetEnvironmentVariable("CRYPT_KEY_ESCROW_INTERVAL");
        if (int.TryParse(envValue, out var hours))
            return hours;

        var config = LoadConfig();
        return config?.Escrow?.KeyEscrowIntervalHours ?? 1;
    }

    /// <summary>
    /// Gets whether to validate the key locally (inspired by Mac Crypt).
    /// </summary>
    public static bool GetValidateKey()
    {
        var envValue = Environment.GetEnvironmentVariable("CRYPT_VALIDATE_KEY");
        if (bool.TryParse(envValue, out var validate))
            return validate;

        var config = LoadConfig();
        return config?.Escrow?.ValidateKey ?? true;
    }

    /// <summary>
    /// Gets users to skip from escrow enforcement (inspired by Mac Crypt).
    /// </summary>
    public static string[]? GetSkipUsers()
    {
        var envValue = Environment.GetEnvironmentVariable("CRYPT_SKIP_USERS");
        if (!string.IsNullOrWhiteSpace(envValue))
            return envValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var config = LoadConfig();
        return config?.Escrow?.SkipUsers;
    }

    /// <summary>
    /// Gets command to run after error conditions (inspired by Mac Crypt).
    /// </summary>
    public static string? GetPostRunCommand()
    {
        var envValue = Environment.GetEnvironmentVariable("CRYPT_POST_RUN_COMMAND");
        if (!string.IsNullOrWhiteSpace(envValue))
            return envValue;

        var config = LoadConfig();
        return config?.Escrow?.PostRunCommand;
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

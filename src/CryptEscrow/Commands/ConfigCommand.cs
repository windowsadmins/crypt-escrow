using CryptEscrow.Services;
using Serilog;

namespace CryptEscrow.Commands;

public static class ConfigCommand
{
    public static void Show()
    {
        var configPath = ConfigService.GetConfigPath();
        
        Console.WriteLine("Configuration");
        Console.WriteLine("=============");
        Console.WriteLine();
        Console.WriteLine($"Config file: {configPath}");
        Console.WriteLine($"File exists: {File.Exists(configPath)}");
        Console.WriteLine();

        // Show effective configuration
        Console.WriteLine("Effective Configuration:");
        Console.WriteLine("------------------------");
        
        var serverUrl = ConfigService.GetServerUrl();
        Console.WriteLine($"  server.url: {serverUrl ?? "(not set)"}");
        Console.WriteLine($"  server.skip_cert_check: {ConfigService.GetSkipCertCheck()}");
        Console.WriteLine($"  escrow.auto_rotate: {ConfigService.GetAutoRotate()}");
        Console.WriteLine($"  escrow.cleanup_old_protectors: {ConfigService.GetCleanupOldProtectors()}");
        Console.WriteLine();

        // Show environment variable overrides
        Console.WriteLine("Environment Variables:");
        Console.WriteLine("----------------------");
        
        var envVars = new[]
        {
            "CRYPT_ESCROW_SERVER_URL",
            "CRYPT_ESCROW_SKIP_CERT_CHECK",
            "CRYPT_ESCROW_AUTO_ROTATE",
            "CRYPT_ESCROW_CLEANUP_OLD_PROTECTORS"
        };

        foreach (var env in envVars)
        {
            var value = Environment.GetEnvironmentVariable(env);
            if (!string.IsNullOrWhiteSpace(value))
            {
                Console.WriteLine($"  {env}={value}");
            }
        }

        // Show last escrowed protector
        var lastProtectorId = ConfigService.GetLastEscrowedProtectorId();
        if (!string.IsNullOrWhiteSpace(lastProtectorId))
        {
            Console.WriteLine();
            Console.WriteLine($"Last escrowed protector: {lastProtectorId}");
        }
    }

    public static void Set(string key, string value)
    {
        try
        {
            ConfigService.SetValue(key, value);
            Console.WriteLine($"Set {key} = {value}");
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to set configuration value");
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}

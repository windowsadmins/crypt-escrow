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
        Console.WriteLine("Precedence: command line > policy > machine settings > environment > config file > default");
        Console.WriteLine($@"Policy:           HKLM\{ConfigService.PolicyKeyPath}");
        Console.WriteLine($@"                  HKLM\{ConfigService.PolicyKeyPathMdm}");
        Console.WriteLine($@"Machine settings: HKLM\{ConfigService.SettingsKeyPath}");
        Console.WriteLine($"Config file:      {configPath} ({(File.Exists(configPath) ? "present" : "absent")})");
        Console.WriteLine();

        // A value set by policy is managed: config set cannot change it.
        Console.WriteLine("Effective Configuration:");
        Console.WriteLine("------------------------");
        foreach (var (name, value, source) in ConfigService.Describe())
        {
            var label = source switch
            {
                SettingSource.Policy => "policy (managed)",
                SettingSource.MachineSettings => "machine settings",
                SettingSource.Environment => "environment",
                SettingSource.LegacyFile => "config file",
                SettingSource.CommandLine => "command line",
                _ => "default"
            };
            Console.WriteLine($"  {name,-24} {value,-40} [{label}]");
        }

        foreach (var note in ConfigService.IgnoredFileNotes)
        {
            Console.WriteLine();
            Console.WriteLine($"  {note}");
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
        catch (UnauthorizedAccessException)
        {
            Log.Error("Administrator privileges required to change machine settings");
            Console.WriteLine("Error: run elevated to change machine settings");
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to set configuration value");
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}

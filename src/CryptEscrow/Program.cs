using System.CommandLine;
using CryptEscrow.Commands;
using CryptEscrow.Services;
using Serilog;

namespace CryptEscrow;

public class Program
{
    public static async Task<int> Main(string[] args)
    {
        // Initialize logging
        var logPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "CryptEscrow", "Logs", $"CryptEscrow_{DateTime.Now:yyyyMMdd}.log");
        
        Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);
        
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss}] [{Level:u3}] {Message:lj}{NewLine}{Exception}")
            .WriteTo.File(logPath, 
                outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss}] [{Level:u3}] {Message:lj}{NewLine}{Exception}",
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 30)
            .CreateLogger();

        try
        {
            var rootCommand = new RootCommand("BitLocker recovery key escrow to Crypt Server")
            {
                Name = "crypt"
            };

            // Global options
            var serverOption = new Option<string?>(
                aliases: ["--server", "-s"],
                description: "Crypt Server URL (or set CRYPT_ESCROW_SERVER_URL)");
            
            var driveOption = new Option<string>(
                aliases: ["--drive", "-d"],
                getDefaultValue: () => "C:",
                description: "Drive letter to escrow");
            
            var skipCertOption = new Option<bool>(
                aliases: ["--skip-cert-check"],
                description: "Skip TLS certificate validation");

            rootCommand.AddGlobalOption(serverOption);
            rootCommand.AddGlobalOption(driveOption);
            rootCommand.AddGlobalOption(skipCertOption);

            // escrow command
            var escrowCommand = new Command("escrow", "Escrow BitLocker recovery key to Crypt Server");
            var forceOption = new Option<bool>(
                aliases: ["--force", "-f"],
                description: "Force escrow even if already escrowed");
            escrowCommand.AddOption(forceOption);
            escrowCommand.SetHandler(async (server, drive, skipCert, force) =>
            {
                var result = await EscrowCommand.ExecuteAsync(server, drive, skipCert, force);
                Environment.ExitCode = result;
            }, serverOption, driveOption, skipCertOption, forceOption);
            rootCommand.AddCommand(escrowCommand);

            // rotate command
            var rotateCommand = new Command("rotate", "Rotate BitLocker recovery key and escrow new key");
            var cleanupOption = new Option<bool>(
                aliases: ["--cleanup", "-c"],
                getDefaultValue: () => true,
                description: "Remove old recovery protectors after rotation");
            rotateCommand.AddOption(cleanupOption);
            rotateCommand.SetHandler(async (server, drive, skipCert, cleanup) =>
            {
                var result = await RotateCommand.ExecuteAsync(server, drive, skipCert, cleanup);
                Environment.ExitCode = result;
            }, serverOption, driveOption, skipCertOption, cleanupOption);
            rootCommand.AddCommand(rotateCommand);

            // verify command
            var verifyCommand = new Command("verify", "Verify if key is escrowed on Crypt Server");
            verifyCommand.SetHandler(async (server, drive, skipCert) =>
            {
                var result = await VerifyCommand.ExecuteAsync(server, drive, skipCert);
                Environment.ExitCode = result;
            }, serverOption, driveOption, skipCertOption);
            rootCommand.AddCommand(verifyCommand);

            // config command
            var configCommand = new Command("config", "Manage configuration");
            
            var configShowCommand = new Command("show", "Show current configuration");
            configShowCommand.SetHandler(() => ConfigCommand.Show());
            configCommand.AddCommand(configShowCommand);
            
            var configSetCommand = new Command("set", "Set configuration value");
            var keyArg = new Argument<string>("key", "Configuration key");
            var valueArg = new Argument<string>("value", "Configuration value");
            configSetCommand.AddArgument(keyArg);
            configSetCommand.AddArgument(valueArg);
            configSetCommand.SetHandler((key, value) => ConfigCommand.Set(key, value), keyArg, valueArg);
            configCommand.AddCommand(configSetCommand);
            
            rootCommand.AddCommand(configCommand);

            // register-task command
            var registerCommand = new Command("register-task", "Register Windows scheduled task");
            var frequencyOption = new Option<string>(
                aliases: ["--frequency", "-f"],
                getDefaultValue: () => "daily",
                description: "Task frequency: hourly, daily, weekly, login");
            registerCommand.AddOption(frequencyOption);
            registerCommand.SetHandler((server, frequency) =>
            {
                var result = RegisterTaskCommand.Execute(server, frequency);
                Environment.ExitCode = result;
            }, serverOption, frequencyOption);
            rootCommand.AddCommand(registerCommand);

            return await rootCommand.InvokeAsync(args);
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Fatal error");
            return ExitCodes.ConfigurationError;
        }
        finally
        {
            await Log.CloseAndFlushAsync();
        }
    }
}

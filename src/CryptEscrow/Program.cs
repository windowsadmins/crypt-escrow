using System.CommandLine;
using CryptEscrow.Commands;
using CryptEscrow.Services;
using Serilog;
using Serilog.Events;

namespace CryptEscrow;

public class Program
{
    private const string ConsoleTemplate =
        "[{Timestamp:HH:mm:ss}] [{Level:u3}] {Message:lj}{NewLine}{Exception}";

    /// <summary>
    /// One line per event: local timestamp, the level padded to five characters, the
    /// message. The level names come from <see cref="LevelNameEnricher"/>.
    /// </summary>
    internal const string FileTemplate =
        "[{Timestamp:yyyy-MM-dd HH:mm:ss}] {LevelName:l} {Message:lj}{NewLine}{Exception}";

    private const int DefaultRetainedDays = 30;

    /// <summary>
    /// %ProgramData%\ManagedEncryption\logs\crypt-escrow.log unless the config says
    /// otherwise. Everything else this tool owns already lives under
    /// ManagedEncryption; the log was the one thing writing to a root of its own, so
    /// the path the installer configures and the docs quote never existed.
    ///
    /// The name is deliberately static. It used to carry the date, which Serilog then
    /// appended its own date to -- so the files read CryptEscrow_2026030220260302.log,
    /// and because every day produced a different base name, retainedFileCountLimit
    /// only ever saw a set of one and never deleted anything. One machine had 179 daily
    /// files against a limit of 30.
    /// </summary>
    internal static string ResolveLogPath(string? configured)
    {
        if (!string.IsNullOrWhiteSpace(configured))
            return configured;

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "ManagedEncryption", "logs", "crypt-escrow.log");
    }

    /// <summary>
    /// Maps a configured level name onto Serilog. An unrecognised or missing value
    /// keeps the previous behaviour rather than silencing the log.
    /// </summary>
    internal static LogEventLevel ParseLevel(string? level)
        => level?.Trim().ToUpperInvariant() switch
        {
            "VERBOSE" => LogEventLevel.Verbose,
            "DEBUG" => LogEventLevel.Debug,
            "INFO" or "INFORMATION" => LogEventLevel.Information,
            "WARN" or "WARNING" => LogEventLevel.Warning,
            "ERROR" => LogEventLevel.Error,
            "FATAL" => LogEventLevel.Fatal,
            _ => LogEventLevel.Information
        };

    /// <summary>
    /// The level the sinks run at. <c>-v</c>/<c>--verbose</c> lowers a quieter
    /// configured level to Debug; a configured level already at or below Debug is kept.
    /// </summary>
    internal static LogEventLevel ResolveLevel(string? configured, bool verbose)
    {
        var level = ParseLevel(configured);
        return verbose && level > LogEventLevel.Debug ? LogEventLevel.Debug : level;
    }

    /// <summary>
    /// Read before the command line is parsed, because the logger has to exist before
    /// the parser can report anything.
    /// </summary>
    internal static bool IsVerbose(string[] args)
        => args.Any(a => a is "-v" or "--verbose");

    public static async Task<int> Main(string[] args)
    {
        var verbose = IsVerbose(args);

        // Console-only until the config is read, so a problem loading it is still seen.
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Is(verbose ? LogEventLevel.Debug : LogEventLevel.Information)
            .WriteTo.Console(outputTemplate: ConsoleTemplate)
            .CreateLogger();

        var logging = ConfigService.LoadConfig()?.Logging;

        var logPath = ResolveLogPath(logging?.FilePath);
        Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Is(ResolveLevel(logging?.Level, verbose))
            .Enrich.With<LevelNameEnricher>()
            .WriteTo.Console(outputTemplate: ConsoleTemplate)
            .WriteTo.File(logPath,
                outputTemplate: FileTemplate,
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: logging?.RetainedDays ?? DefaultRetainedDays,
                shared: true)
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

            var verboseOption = new Option<bool>(
                aliases: ["--verbose", "-v"],
                description: "Log at Debug level to the console and the log file");

            rootCommand.AddGlobalOption(serverOption);
            rootCommand.AddGlobalOption(driveOption);
            rootCommand.AddGlobalOption(skipCertOption);
            rootCommand.AddGlobalOption(verboseOption);

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

            await rootCommand.InvokeAsync(args);
            return Environment.ExitCode;
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

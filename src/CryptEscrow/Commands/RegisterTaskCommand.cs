using CryptEscrow.Services;
using Serilog;
using System.Diagnostics;

namespace CryptEscrow.Commands;

public static class RegisterTaskCommand
{
    public static int Execute(string? serverUrl, string frequency)
    {
        // Check for admin privileges
        var isAdmin = new System.Security.Principal.WindowsPrincipal(
            System.Security.Principal.WindowsIdentity.GetCurrent())
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);

        if (!isAdmin)
        {
            Log.Error("Administrator privileges required to register scheduled task");
            return ExitCodes.ConfigurationError;
        }

        var taskName = "CryptEscrow - BitLocker Key Sync";
        var exePath = Process.GetCurrentProcess().MainModule?.FileName 
            ?? Path.Combine(AppContext.BaseDirectory, "crypt-escrow.exe");

        // Build the command
        var arguments = "escrow";
        if (!string.IsNullOrWhiteSpace(serverUrl))
        {
            arguments += $" --server \"{serverUrl}\"";
        }

        Log.Information("Registering scheduled task: {TaskName}", taskName);

        try
        {
            // Remove existing task if present
            RunSchtasks($"/Delete /TN \"{taskName}\" /F");

            // Build trigger based on frequency
            var scheduleArgs = frequency.ToLower() switch
            {
                "hourly" => "/SC HOURLY",
                "daily" => "/SC DAILY /ST 08:00",
                "weekly" => "/SC WEEKLY /D MON /ST 08:00",
                "login" => "/SC ONLOGON",
                _ => throw new ArgumentException($"Invalid frequency: {frequency}")
            };

            // Create the task
            var createArgs = $"/Create /TN \"{taskName}\" /TR \"\\\"{exePath}\\\" {arguments}\" {scheduleArgs} /RU SYSTEM /RL HIGHEST /F";
            
            var (exitCode, output) = RunSchtasks(createArgs);
            
            if (exitCode == 0)
            {
                Log.Information("Scheduled task registered successfully ({Frequency})", frequency);
                Console.WriteLine($"Task '{taskName}' registered with {frequency} schedule");
                return ExitCodes.Success;
            }
            else
            {
                Log.Error("Failed to create scheduled task: {Output}", output);
                return ExitCodes.ConfigurationError;
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to register scheduled task");
            return ExitCodes.ConfigurationError;
        }
    }

    private static (int exitCode, string output) RunSchtasks(string arguments)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = "schtasks.exe",
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        process.Start();
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        return (process.ExitCode, string.IsNullOrWhiteSpace(output) ? error : output);
    }
}

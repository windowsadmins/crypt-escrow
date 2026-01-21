using System.Diagnostics;
using System.Text.RegularExpressions;
using Serilog;

namespace CryptEscrow.Services;

/// <summary>
/// Service for interacting with BitLocker via manage-bde and PowerShell.
/// </summary>
public partial class BitLockerService
{
    /// <summary>
    /// Gets the BitLocker volume status for a drive.
    /// </summary>
    public async Task<BitLockerVolume?> GetVolumeAsync(string drive)
    {
        try
        {
            Log.Debug("Getting BitLocker volume info for {Drive}", drive);
            
            // Use PowerShell to get BitLocker info (more reliable than parsing manage-bde)
            var script = $@"
                $vol = Get-BitLockerVolume -MountPoint '{drive}' -ErrorAction Stop
                $protectors = $vol.KeyProtector | Where-Object {{ $_.KeyProtectorType -eq 'RecoveryPassword' }}
                [PSCustomObject]@{{
                    VolumeStatus = $vol.VolumeStatus.ToString()
                    ProtectionStatus = $vol.ProtectionStatus.ToString()
                    Protectors = @($protectors | ForEach-Object {{
                        [PSCustomObject]@{{
                            Id = $_.KeyProtectorId
                            RecoveryPassword = $_.RecoveryPassword
                        }}
                    }})
                }} | ConvertTo-Json -Depth 3
            ";

            var result = await RunPowerShellAsync(script);
            if (string.IsNullOrWhiteSpace(result))
            {
                Log.Warning("No BitLocker info returned for {Drive}", drive);
                return null;
            }

            var json = System.Text.Json.JsonDocument.Parse(result);
            var root = json.RootElement;
            
            var volume = new BitLockerVolume
            {
                Drive = drive,
                VolumeStatus = root.GetProperty("VolumeStatus").GetString() ?? "Unknown",
                ProtectionStatus = root.GetProperty("ProtectionStatus").GetString() ?? "Unknown",
                RecoveryProtectors = []
            };

            if (root.TryGetProperty("Protectors", out var protectors))
            {
                foreach (var p in protectors.EnumerateArray())
                {
                    volume.RecoveryProtectors.Add(new RecoveryProtector
                    {
                        KeyProtectorId = p.GetProperty("Id").GetString() ?? "",
                        RecoveryPassword = p.GetProperty("RecoveryPassword").GetString() ?? ""
                    });
                }
            }

            Log.Debug("BitLocker status: {Status}, Protectors: {Count}", 
                volume.VolumeStatus, volume.RecoveryProtectors.Count);
            
            return volume;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to get BitLocker volume info for {Drive}", drive);
            return null;
        }
    }

    /// <summary>
    /// Creates a new recovery password protector.
    /// </summary>
    public async Task<RecoveryProtector?> CreateRecoveryProtectorAsync(string drive)
    {
        try
        {
            Log.Information("Creating new recovery password protector on {Drive}", drive);

            var script = $@"
                Add-BitLockerKeyProtector -MountPoint '{drive}' -RecoveryPasswordProtector -ErrorAction Stop | Out-Null
                $vol = Get-BitLockerVolume -MountPoint '{drive}' -ErrorAction Stop
                $newest = $vol.KeyProtector | Where-Object {{ $_.KeyProtectorType -eq 'RecoveryPassword' }} | Select-Object -Last 1
                [PSCustomObject]@{{
                    Id = $newest.KeyProtectorId
                    RecoveryPassword = $newest.RecoveryPassword
                }} | ConvertTo-Json
            ";

            var result = await RunPowerShellAsync(script);
            if (string.IsNullOrWhiteSpace(result))
            {
                Log.Error("Failed to create recovery protector on {Drive}", drive);
                return null;
            }

            var json = System.Text.Json.JsonDocument.Parse(result);
            var root = json.RootElement;

            var protector = new RecoveryProtector
            {
                KeyProtectorId = root.GetProperty("Id").GetString() ?? "",
                RecoveryPassword = root.GetProperty("RecoveryPassword").GetString() ?? ""
            };

            Log.Information("Created protector: {Id}", protector.KeyProtectorId);
            return protector;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to create recovery protector on {Drive}", drive);
            return null;
        }
    }

    /// <summary>
    /// Removes a recovery password protector.
    /// </summary>
    public async Task<bool> RemoveProtectorAsync(string drive, string protectorId)
    {
        try
        {
            Log.Information("Removing protector {Id} from {Drive}", protectorId, drive);

            var script = $@"
                Remove-BitLockerKeyProtector -MountPoint '{drive}' -KeyProtectorId '{protectorId}' -ErrorAction Stop
            ";

            await RunPowerShellAsync(script);
            Log.Information("Removed protector {Id}", protectorId);
            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to remove protector {Id} from {Drive}", protectorId, drive);
            return false;
        }
    }

    private static async Task<string> RunPowerShellAsync(string script)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{script.Replace("\"", "\\\"")}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        process.Start();
        var output = await process.StandardOutput.ReadToEndAsync();
        var error = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        if (process.ExitCode != 0 && !string.IsNullOrWhiteSpace(error))
        {
            Log.Warning("PowerShell error: {Error}", error.Trim());
        }

        return output.Trim();
    }
}

public class BitLockerVolume
{
    public required string Drive { get; set; }
    public required string VolumeStatus { get; set; }
    public required string ProtectionStatus { get; set; }
    public required List<RecoveryProtector> RecoveryProtectors { get; set; }
    
    public bool IsEncrypted => VolumeStatus != "FullyDecrypted";
    public RecoveryProtector? PrimaryProtector => RecoveryProtectors.FirstOrDefault();
}

public class RecoveryProtector
{
    public required string KeyProtectorId { get; set; }
    public required string RecoveryPassword { get; set; }
}

using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Security.Principal;
using Serilog;

namespace CryptEscrow.Services;

/// <summary>
/// Service for interacting with BitLocker via manage-bde and PowerShell.
/// </summary>
public partial class BitLockerService
{
    /// <summary>
    /// Checks if the current process is running with administrator privileges.
    /// </summary>
    public static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }
    /// <summary>
    /// Gets the BitLocker volume status for a drive.
    /// </summary>
    public async Task<BitLockerVolume?> GetVolumeAsync(string drive)
    {
        try
        {
            Log.Debug("Getting BitLocker volume info for {Drive}", drive);
            
            // Use PowerShell to get BitLocker info (more reliable than parsing manage-bde)
            // $WarningPreference and $ProgressPreference suppress non-JSON output
            var script = $@"
                $WarningPreference = 'SilentlyContinue'
                $ProgressPreference = 'SilentlyContinue'
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
                }} | ConvertTo-Json -Depth 3 -Compress
            ";

            var (result, error) = await RunPowerShellAsync(script);
            
            // Check for access denied error
            if (!string.IsNullOrWhiteSpace(error) && 
                (error.Contains("Access denied") || error.Contains("Access is denied") || error.Contains("0x80041003")))
            {
                Log.Error("Access denied: BitLocker operations require administrator privileges");
                throw new UnauthorizedAccessException("Administrator privileges required for BitLocker operations");
            }
            
            if (string.IsNullOrWhiteSpace(result))
            {
                Log.Warning("No BitLocker info returned for {Drive}", drive);
                return null;
            }

            // Extract JSON in case there's non-JSON text in output
            var jsonText = ExtractJson(result) ?? result;
            var json = System.Text.Json.JsonDocument.Parse(jsonText);
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

            // $WarningPreference and $ProgressPreference suppress non-JSON output
            var script = $@"
                $WarningPreference = 'SilentlyContinue'
                $ProgressPreference = 'SilentlyContinue'
                Add-BitLockerKeyProtector -MountPoint '{drive}' -RecoveryPasswordProtector -ErrorAction Stop | Out-Null
                $vol = Get-BitLockerVolume -MountPoint '{drive}' -ErrorAction Stop
                $newest = $vol.KeyProtector | Where-Object {{ $_.KeyProtectorType -eq 'RecoveryPassword' }} | Select-Object -Last 1
                [PSCustomObject]@{{
                    Id = $newest.KeyProtectorId
                    RecoveryPassword = $newest.RecoveryPassword
                }} | ConvertTo-Json -Compress
            ";

            var (result, error) = await RunPowerShellAsync(script);
            
            // Check for access denied error
            if (!string.IsNullOrWhiteSpace(error) && 
                (error.Contains("Access denied") || error.Contains("Access is denied") || error.Contains("0x80041003")))
            {
                Log.Error("Access denied: BitLocker operations require administrator privileges");
                throw new UnauthorizedAccessException("Administrator privileges required for BitLocker operations");
            }
            
            if (string.IsNullOrWhiteSpace(result))
            {
                Log.Error("Failed to create recovery protector on {Drive}", drive);
                return null;
            }

            // Extract JSON in case there's non-JSON text in output
            var jsonText = ExtractJson(result) ?? result;
            var json = System.Text.Json.JsonDocument.Parse(jsonText);
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

            // $WarningPreference and $ProgressPreference suppress non-JSON output
            var script = $@"
                $WarningPreference = 'SilentlyContinue'
                $ProgressPreference = 'SilentlyContinue'
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

    private static async Task<(string output, string error)> RunPowerShellAsync(string script)
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

        return (output.Trim(), error.Trim());
    }

    /// <summary>
    /// Extracts JSON from PowerShell output that may contain non-JSON text.
    /// Looks for content starting with { or [ and ending with } or ].
    /// </summary>
    private static string? ExtractJson(string output)
    {
        if (string.IsNullOrWhiteSpace(output))
            return null;

        // Try to find JSON object or array in the output
        var startIndex = output.IndexOfAny(['{', '[']);
        if (startIndex < 0)
            return null;

        var startChar = output[startIndex];
        var endChar = startChar == '{' ? '}' : ']';
        var lastEndIndex = output.LastIndexOf(endChar);
        
        if (lastEndIndex <= startIndex)
            return null;

        return output[startIndex..(lastEndIndex + 1)];
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

using System.Diagnostics;
using Serilog;

namespace CryptEscrow.Services;

/// <summary>
/// Service for retrieving device information.
/// Uses PowerShell/WMI via subprocess to avoid System.Management trimming issues.
/// </summary>
public class DeviceInfoService
{
    /// <summary>
    /// Gets the device serial number.
    /// </summary>
    public string GetSerial()
    {
        try
        {
            // Try Win32_ComputerSystemProduct first via PowerShell
            var serial = RunPowerShell("(Get-CimInstance Win32_ComputerSystemProduct).IdentifyingNumber");
            if (IsValidSerial(serial))
            {
                Log.Debug("Device serial (ComputerSystemProduct): {Serial}", serial);
                return serial;
            }

            // Fallback to BIOS
            serial = RunPowerShell("(Get-CimInstance Win32_BIOS).SerialNumber");
            if (IsValidSerial(serial))
            {
                Log.Debug("Device serial (BIOS): {Serial}", serial);
                return serial;
            }

            // Final fallback to machine GUID
            var machineGuid = Microsoft.Win32.Registry.GetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography",
                "MachineGuid", null)?.ToString();
            
            if (!string.IsNullOrWhiteSpace(machineGuid))
            {
                var vmSerial = $"VM-{machineGuid}";
                Log.Debug("Device serial (MachineGuid): {Serial}", vmSerial);
                return vmSerial;
            }

            return Environment.MachineName;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to get device serial");
            return Environment.MachineName;
        }
    }

    /// <summary>
    /// Gets the currently logged-in username.
    /// </summary>
    public string GetCurrentUsername()
    {
        try
        {
            // Try to get owner of explorer.exe via PowerShell
            var result = RunPowerShell(
                "$p = Get-CimInstance Win32_Process -Filter \"Name='explorer.exe'\" | Select-Object -First 1; " +
                "if ($p) { $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner; " +
                "if ($o.Domain) { \"$($o.Domain)\\$($o.User)\" } else { $o.User } }");
            
            if (!string.IsNullOrWhiteSpace(result))
            {
                Log.Debug("Current user (explorer): {Username}", result);
                return result;
            }
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "Failed to get user from explorer process");
        }

        // Fallback to current identity
        var identity = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
        Log.Debug("Current user (identity): {Username}", identity);
        return identity;
    }

    /// <summary>
    /// Gets the computer name.
    /// </summary>
    public string GetMachineName() => Environment.MachineName;

    private static bool IsValidSerial(string? serial)
    {
        return !string.IsNullOrWhiteSpace(serial) &&
               serial != "System Serial Number" &&
               serial != "To Be Filled By O.E.M." &&
               serial != "Default string";
    }

    private static string RunPowerShell(string command)
    {
        try
        {
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NoLogo -Command \"{command}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            
            process.Start();
            var output = process.StandardOutput.ReadToEnd().Trim();
            process.WaitForExit(5000);
            
            return output;
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "PowerShell command failed: {Command}", command);
            return string.Empty;
        }
    }
}

using System.Management;
using Serilog;

namespace CryptEscrow.Services;

/// <summary>
/// Service for retrieving device information.
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
            // Try Win32_ComputerSystemProduct first
            using var searcher = new ManagementObjectSearcher("SELECT IdentifyingNumber FROM Win32_ComputerSystemProduct");
            foreach (var obj in searcher.Get())
            {
                var serial = obj["IdentifyingNumber"]?.ToString()?.Trim();
                if (!string.IsNullOrWhiteSpace(serial) && 
                    serial != "System Serial Number" &&
                    serial != "To Be Filled By O.E.M." &&
                    serial != "Default string")
                {
                    Log.Debug("Device serial (ComputerSystemProduct): {Serial}", serial);
                    return serial;
                }
            }

            // Fallback to BIOS
            using var biosSearcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS");
            foreach (var obj in biosSearcher.Get())
            {
                var serial = obj["SerialNumber"]?.ToString()?.Trim();
                if (!string.IsNullOrWhiteSpace(serial) &&
                    serial != "System Serial Number" &&
                    serial != "To Be Filled By O.E.M.")
                {
                    Log.Debug("Device serial (BIOS): {Serial}", serial);
                    return serial;
                }
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
            // Try to get owner of explorer.exe
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_Process WHERE Name = 'explorer.exe'");
            
            foreach (ManagementObject obj in searcher.Get())
            {
                var outParams = obj.InvokeMethod("GetOwner", null, null);
                if (outParams != null)
                {
                    var user = outParams["User"]?.ToString();
                    var domain = outParams["Domain"]?.ToString();
                    
                    if (!string.IsNullOrWhiteSpace(user))
                    {
                        var username = string.IsNullOrWhiteSpace(domain) 
                            ? user 
                            : $"{domain}\\{user}";
                        Log.Debug("Current user (explorer): {Username}", username);
                        return username;
                    }
                }
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
}

using CryptEscrow.Services;
using Serilog;

namespace CryptEscrow.Commands;

public static class RotateCommand
{
    public static async Task<int> ExecuteAsync(string? serverUrl, string drive, bool skipCert, bool cleanup)
    {
        // Check for admin privileges first
        if (!BitLockerService.IsElevated())
        {
            Log.Error("Administrator privileges required to access BitLocker. Please run as administrator.");
            return ExitCodes.PermissionDenied;
        }

        // Resolve server URL
        var url = ConfigService.GetServerUrl(serverUrl);
        if (string.IsNullOrWhiteSpace(url))
        {
            Log.Error("No server URL configured");
            return ExitCodes.ConfigurationError;
        }

        Log.Information("Starting key rotation on {Drive}", drive);

        var bitlocker = new BitLockerService();
        
        try
        {
            var volume = await bitlocker.GetVolumeAsync(drive);

            if (volume == null || !volume.IsEncrypted)
            {
                Log.Error("BitLocker is not enabled on {Drive}", drive);
                return ExitCodes.BitLockerNotEnabled;
            }

            var oldProtector = volume.PrimaryProtector;
            if (oldProtector == null)
            {
                Log.Error("No recovery password protector found on {Drive}", drive);
                return ExitCodes.NoRecoveryProtector;
            }

            var oldProtectorId = oldProtector.KeyProtectorId;
            Log.Information("Current protector: {Id}", oldProtectorId);

            // Create new recovery protector
            var newProtector = await bitlocker.CreateRecoveryProtectorAsync(drive);
            if (newProtector == null)
            {
                Log.Error("Failed to create new recovery protector");
                return ExitCodes.RotationFailed;
            }

            Log.Information("Created new protector: {Id}", newProtector.KeyProtectorId);

            // Escrow new key
            var deviceInfo = new DeviceInfoService();
            var serial = deviceInfo.GetSerial();
            var username = deviceInfo.GetCurrentUsername();
            var machineName = deviceInfo.GetMachineName();

            var skipCertCheck = ConfigService.GetSkipCertCheck(skipCert);
            var authConfig = ConfigService.GetAuthConfig();
            using var client = new CryptServerClient(url, skipCertCheck, authConfig);

            await client.CheckinAsync(new CheckinRequest
            {
                Serial = serial,
                RecoveryPassword = newProtector.RecoveryPassword,
                Username = username,
                MachineName = machineName
            });

            Log.Information("New key escrowed successfully");

            // Save marker
            ConfigService.SaveEscrowedProtectorId(newProtector.KeyProtectorId);

            // Cleanup old protectors
            if (cleanup)
            {
                // Get updated volume info
                var updatedVolume = await bitlocker.GetVolumeAsync(drive);
                if (updatedVolume != null)
                {
                    var removedCount = 0;
                    foreach (var protector in updatedVolume.RecoveryProtectors)
                    {
                        if (protector.KeyProtectorId != newProtector.KeyProtectorId)
                        {
                            if (await bitlocker.RemoveProtectorAsync(drive, protector.KeyProtectorId))
                            {
                                removedCount++;
                            }
                        }
                    }
                    
                    if (removedCount > 0)
                    {
                        Log.Information("Removed {Count} old protector(s)", removedCount);
                    }
                }
            }

            Log.Information("Key rotation completed successfully");
            return ExitCodes.Success;
        }
        catch (UnauthorizedAccessException ex)
        {
            Log.Error(ex, "Access denied");
            return ExitCodes.PermissionDenied;
        }
        catch (CryptServerException ex)
        {
            Log.Error(ex, "Failed during key rotation");
            return ExitCodes.NetworkError;
        }
    }
}

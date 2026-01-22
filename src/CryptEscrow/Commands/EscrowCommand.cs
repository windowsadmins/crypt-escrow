using CryptEscrow.Services;
using Serilog;

namespace CryptEscrow.Commands;

public static class EscrowCommand
{
    public static async Task<int> ExecuteAsync(string? serverUrl, string drive, bool skipCert, bool force)
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
            Log.Error("No server URL configured. Use --server, config file, or CRYPT_ESCROW_SERVER_URL environment variable.");
            return ExitCodes.ConfigurationError;
        }

        Log.Information("Starting BitLocker key escrow to {Url}", url);

        // Get BitLocker info
        var bitlocker = new BitLockerService();
        
        // Get device info early - needed for both verify and escrow
        var deviceInfo = new DeviceInfoService();
        var serial = deviceInfo.GetSerial();
        var username = deviceInfo.GetCurrentUsername();
        var machineName = deviceInfo.GetMachineName();
        
        // Resolve auth config
        var skipCertCheck = ConfigService.GetSkipCertCheck(skipCert);
        var authConfig = ConfigService.GetAuthConfig();
        
        try
        {
            var volume = await bitlocker.GetVolumeAsync(drive);

            if (volume == null)
            {
                Log.Error("Failed to get BitLocker volume info for {Drive}", drive);
                return ExitCodes.BitLockerNotEnabled;
            }

            if (!volume.IsEncrypted)
            {
                Log.Warning("BitLocker is not enabled on {Drive}", drive);
                return ExitCodes.BitLockerNotEnabled;
            }

            var protector = volume.PrimaryProtector;
            if (protector == null)
            {
                Log.Error("No recovery password protector found on {Drive}", drive);
                return ExitCodes.NoRecoveryProtector;
            }

            // Check if we should escrow based on interval
            if (!force && !ConfigService.ShouldEscrowNow())
            {
                var lastEscrow = ConfigService.GetLastEscrowTimestamp();
                var intervalHours = ConfigService.GetKeyEscrowIntervalHours();
                var nextEscrow = lastEscrow?.AddHours(intervalHours);
                
                Log.Information("Escrow interval not elapsed. Last escrow: {LastEscrow}, Next escrow: {NextEscrow}", 
                    lastEscrow, nextEscrow);
                return ExitCodes.AlreadyEscrowed;
            }

            // Check if already escrowed (same protector)
            if (!force)
            {
                var lastProtectorId = ConfigService.GetLastEscrowedProtectorId();
                if (lastProtectorId == protector.KeyProtectorId)
                {
                    // Verify with server that the key is actually escrowed
                    using var verifyClient = new CryptServerClient(url, skipCertCheck, authConfig);
                    
                    try
                    {
                        var verifyResult = await verifyClient.VerifyAsync(serial);
                        
                        if (verifyResult.Escrowed)
                        {
                            Log.Information("Key already escrowed and verified on server (protector: {Id})", protector.KeyProtectorId);
                            return ExitCodes.AlreadyEscrowed;
                        }
                        else
                        {
                            Log.Warning("Local cache shows escrowed but server has no record. Re-escrowing...");
                            // Continue to escrow
                        }
                    }
                    catch (CryptServerAuthException ex)
                    {
                        Log.Error("Server authentication failed: {Message}", ex.Message);
                        return ExitCodes.AuthenticationError;
                    }
                    catch (Exception ex)
                    {
                        Log.Warning("Could not verify with server ({Error}). Assuming cached escrow is valid.", ex.Message);
                        return ExitCodes.AlreadyEscrowed;
                    }
                }
            }

            Log.Information("Device: {Serial} ({MachineName}), User: {Username}", serial, machineName, username);

            // Send to Crypt Server
            using var client = new CryptServerClient(url, skipCertCheck, authConfig);

            var response = await client.CheckinAsync(new CheckinRequest
            {
                Serial = serial,
                RecoveryPassword = protector.RecoveryPassword,
                Username = username,
                MachineName = machineName
            });

            // Save marker
            ConfigService.SaveEscrowedProtectorId(protector.KeyProtectorId);

            Log.Information("Key escrowed successfully");

            if (response.RotationRequired)
            {
                Log.Warning("Server requested key rotation");
                
                if (ConfigService.GetAutoRotate())
                {
                    Log.Information("Auto-rotating key...");
                    return await RotateCommand.ExecuteAsync(serverUrl, drive, skipCert, ConfigService.GetCleanupOldProtectors());
                }
            }

            return ExitCodes.Success;
        }
        catch (UnauthorizedAccessException ex)
        {
            Log.Error(ex, "Access denied");
            return ExitCodes.PermissionDenied;
        }
        catch (CryptServerAuthException ex)
        {
            Log.Error("Authentication error: {Message}", ex.Message);
            return ExitCodes.AuthenticationError;
        }
        catch (CryptServerException ex)
        {
            Log.Error(ex, "Failed to escrow key to Crypt Server");
            return ExitCodes.NetworkError;
        }
    }
}

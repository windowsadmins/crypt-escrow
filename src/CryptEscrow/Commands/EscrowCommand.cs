using CryptEscrow.Services;
using Serilog;

namespace CryptEscrow.Commands;

public static class EscrowCommand
{
    public static async Task<int> ExecuteAsync(string? serverUrl, string drive, bool skipCert, bool force)
    {
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

        // Check if already escrowed
        if (!force)
        {
            var lastProtectorId = ConfigService.GetLastEscrowedProtectorId();
            if (lastProtectorId == protector.KeyProtectorId)
            {
                Log.Information("Key already escrowed (protector: {Id})", protector.KeyProtectorId);
                return ExitCodes.AlreadyEscrowed;
            }
        }

        // Get device info
        var deviceInfo = new DeviceInfoService();
        var serial = deviceInfo.GetSerial();
        var username = deviceInfo.GetCurrentUsername();
        var machineName = deviceInfo.GetMachineName();

        Log.Information("Device: {Serial} ({MachineName}), User: {Username}", serial, machineName, username);

        // Send to Crypt Server
        try
        {
            var skipCertCheck = ConfigService.GetSkipCertCheck(skipCert);
            using var client = new CryptServerClient(url, skipCertCheck);

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
        catch (CryptServerException ex)
        {
            Log.Error(ex, "Failed to escrow key to Crypt Server");
            return ExitCodes.NetworkError;
        }
    }
}

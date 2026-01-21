using CryptEscrow.Services;
using Serilog;

namespace CryptEscrow.Commands;

public static class VerifyCommand
{
    public static async Task<int> ExecuteAsync(string? serverUrl, string drive, bool skipCert)
    {
        // Resolve server URL
        var url = ConfigService.GetServerUrl(serverUrl);
        if (string.IsNullOrWhiteSpace(url))
        {
            Log.Error("No server URL configured");
            return ExitCodes.ConfigurationError;
        }

        var deviceInfo = new DeviceInfoService();
        var serial = deviceInfo.GetSerial();

        Log.Information("Verifying escrow status for {Serial}", serial);

        try
        {
            var skipCertCheck = ConfigService.GetSkipCertCheck(skipCert);
            using var client = new CryptServerClient(url, skipCertCheck);

            var response = await client.VerifyAsync(serial);

            if (response.Escrowed)
            {
                Log.Information("Key IS escrowed on Crypt Server");
                if (!string.IsNullOrWhiteSpace(response.DateEscrowed))
                {
                    Log.Information("Date escrowed: {Date}", response.DateEscrowed);
                }
                return ExitCodes.Success;
            }
            else
            {
                Log.Warning("Key is NOT escrowed on Crypt Server");
                return ExitCodes.NoRecoveryProtector;
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to verify escrow status");
            return ExitCodes.NetworkError;
        }
    }
}

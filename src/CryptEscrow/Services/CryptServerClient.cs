using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Serilog;

namespace CryptEscrow.Services;

/// <summary>
/// Client for Crypt Server API.
/// </summary>
public class CryptServerClient : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly string _serverUrl;

    public CryptServerClient(string serverUrl, bool skipCertificateCheck = false)
    {
        _serverUrl = serverUrl.TrimEnd('/');
        
        var handler = new HttpClientHandler();
        if (skipCertificateCheck)
        {
            handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
            Log.Warning("TLS certificate validation disabled");
        }

        _httpClient = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
        _httpClient.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));
    }

    /// <summary>
    /// Sends a BitLocker recovery key to the Crypt Server.
    /// </summary>
    public async Task<CheckinResponse> CheckinAsync(CheckinRequest request, int retryCount = 3)
    {
        var url = $"{_serverUrl}/checkin/";
        Log.Information("Sending key to Crypt Server: {Url}", url);

        Exception? lastException = null;
        
        for (int attempt = 1; attempt <= retryCount; attempt++)
        {
            try
            {
                var content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["serial"] = request.Serial,
                    ["recovery_password"] = request.RecoveryPassword,
                    ["username"] = request.Username,
                    ["macname"] = request.MachineName,
                    ["secret_type"] = request.SecretType
                });

                var response = await _httpClient.PostAsync(url, content);
                response.EnsureSuccessStatusCode();

                var json = await response.Content.ReadAsStringAsync();
                Log.Debug("Server response: {Json}", json);

                var result = JsonSerializer.Deserialize<CheckinResponse>(json, JsonOptions);
                return result ?? new CheckinResponse();
            }
            catch (Exception ex)
            {
                lastException = ex;
                Log.Warning("Checkin attempt {Attempt} failed: {Error}", attempt, ex.Message);

                if (attempt < retryCount)
                {
                    var delay = TimeSpan.FromSeconds(5 * Math.Pow(2, attempt - 1));
                    Log.Debug("Retrying in {Delay} seconds...", delay.TotalSeconds);
                    await Task.Delay(delay);
                }
            }
        }

        Log.Error(lastException, "All checkin attempts failed");
        throw new CryptServerException($"Failed to checkin after {retryCount} attempts", lastException);
    }

    /// <summary>
    /// Verifies if a key has been escrowed for a device.
    /// </summary>
    public async Task<VerifyResponse> VerifyAsync(string serial, string secretType = "recovery_key")
    {
        var url = $"{_serverUrl}/verify/{Uri.EscapeDataString(serial)}/{Uri.EscapeDataString(secretType)}/";
        Log.Debug("Verifying escrow at: {Url}", url);

        try
        {
            var response = await _httpClient.GetAsync(url);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<VerifyResponse>(json, JsonOptions);
            return result ?? new VerifyResponse();
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to verify escrow status");
            return new VerifyResponse { Escrowed = false, Error = ex.Message };
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    public void Dispose()
    {
        _httpClient.Dispose();
        GC.SuppressFinalize(this);
    }
}

public class CheckinRequest
{
    public required string Serial { get; set; }
    public required string RecoveryPassword { get; set; }
    public required string Username { get; set; }
    public required string MachineName { get; set; }
    public string SecretType { get; set; } = "recovery_key";
}

public class CheckinResponse
{
    [JsonPropertyName("serial")]
    public string? Serial { get; set; }
    
    [JsonPropertyName("username")]
    public string? Username { get; set; }
    
    [JsonPropertyName("rotation_required")]
    public bool RotationRequired { get; set; }
    
    [JsonPropertyName("new_secret_escrowed")]
    public bool NewSecretEscrowed { get; set; }
}

public class VerifyResponse
{
    [JsonPropertyName("escrowed")]
    public bool Escrowed { get; set; }
    
    [JsonPropertyName("date_escrowed")]
    public string? DateEscrowed { get; set; }
    
    public string? Error { get; set; }
}

public class CryptServerException : Exception
{
    public CryptServerException(string message, Exception? inner = null) 
        : base(message, inner) { }
}

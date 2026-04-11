using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using Serilog;

namespace CryptEscrow.Services;

/// <summary>
/// Client for Crypt Server API with API key and mTLS authentication support.
/// </summary>
public class CryptServerClient : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly string _serverUrl;
    private readonly AuthConfig? _authConfig;
    private readonly X509Certificate2? _clientCert;

    /// <summary>
    /// Creates a new CryptServerClient with optional authentication.
    /// </summary>
    /// <param name="serverUrl">The Crypt Server URL</param>
    /// <param name="skipCertificateCheck">Skip TLS certificate validation</param>
    /// <param name="authConfig">Authentication configuration (API key or mTLS)</param>
    public CryptServerClient(string serverUrl, bool skipCertificateCheck = false, AuthConfig? authConfig = null)
    {
        _serverUrl = serverUrl.TrimEnd('/');
        _authConfig = authConfig;

        var handler = new HttpClientHandler();

        // Configure TLS certificate validation
        if (skipCertificateCheck)
        {
            handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
            Log.Warning("TLS certificate validation disabled");
        }

        // Configure mTLS if enabled
        if (authConfig?.UseMtls == true)
        {
            _clientCert = GetClientCertificate(authConfig);
            if (_clientCert != null)
            {
                handler.ClientCertificates.Add(_clientCert);
            }
            else
            {
                Log.Warning("mTLS enabled but no valid certificate found");
            }
        }

        _httpClient = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(30)
        };

        _httpClient.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));

        // Configure API key authentication
        if (!string.IsNullOrWhiteSpace(authConfig?.ApiKey))
        {
            var headerName = authConfig.ApiKeyHeader ?? "X-API-Key";
            _httpClient.DefaultRequestHeaders.Add(headerName, authConfig.ApiKey);
            Log.Debug("API key authentication configured with header: {Header}", headerName);
        }
    }

    /// <summary>
    /// Resolves a client certificate for mTLS, trying strategies in priority order
    /// (most secure first): PFX+Credential Manager, then PEM+key files, then Windows
    /// Certificate Store by thumbprint, then Certificate Store by subject name.
    /// </summary>
    private static X509Certificate2? GetClientCertificate(AuthConfig authConfig)
    {
        // Strategy 1: PFX file with passphrase from Windows Credential Manager.
        // Preferred file-based option — key material is encrypted at rest and the
        // passphrase never touches YAML, environment variables, or the registry.
        if (!string.IsNullOrWhiteSpace(authConfig.PfxPath))
        {
            var cert = LoadFromPfxFile(authConfig);
            if (cert != null)
                return cert;
        }

        // Strategy 2: PEM certificate + unencrypted private key file.
        // Least preferred file-based option — private key is plaintext on disk.
        if (!string.IsNullOrWhiteSpace(authConfig.ClientCertPath) &&
            !string.IsNullOrWhiteSpace(authConfig.ClientKeyPath))
        {
            var cert = LoadFromPemFiles(authConfig);
            if (cert != null)
                return cert;
        }

        // Strategies 3 & 4: Windows Certificate Store, by thumbprint then subject.
        // Most secure overall — private key DPAPI-protected and can be non-exportable.
        return LoadFromCertStore(authConfig);
    }

    /// <summary>
    /// Loads a PFX client certificate from disk using a passphrase retrieved from
    /// Windows Credential Manager. Returns null on any failure so the caller can
    /// fall through to the next strategy.
    /// </summary>
    private static X509Certificate2? LoadFromPfxFile(AuthConfig authConfig)
    {
        var pfxPath = authConfig.PfxPath!;
        try
        {
            if (!File.Exists(pfxPath))
            {
                Log.Error("PFX file not found: {Path}", pfxPath);
                return null;
            }

            string? password = null;
            if (!string.IsNullOrWhiteSpace(authConfig.PfxPasswordCredential))
            {
                password = CredentialManager.ReadGenericPassword(authConfig.PfxPasswordCredential);
                if (password == null)
                {
                    Log.Error(
                        "PFX passphrase not found in Credential Manager (target: {Target}); cannot load {Path}",
                        authConfig.PfxPasswordCredential, pfxPath);
                    return null;
                }
            }

            var cert = X509CertificateLoader.LoadPkcs12FromFile(pfxPath, password);
            Log.Information("mTLS enabled via PFX file: {Path}", pfxPath);
            return cert;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to load PFX file {Path}", pfxPath);
            return null;
        }
    }

    /// <summary>
    /// Loads a PEM certificate + private key from disk. Performs a PFX round-trip
    /// so the resulting private key is associated with a key container that
    /// HttpClient can use during the TLS handshake on Windows.
    /// </summary>
    private static X509Certificate2? LoadFromPemFiles(AuthConfig authConfig)
    {
        var certPath = authConfig.ClientCertPath!;
        var keyPath = authConfig.ClientKeyPath!;
        try
        {
            if (!File.Exists(certPath))
            {
                Log.Error("Client certificate PEM file not found: {Path}", certPath);
                return null;
            }
            if (!File.Exists(keyPath))
            {
                Log.Error("Client private key file not found: {Path}", keyPath);
                return null;
            }

            using var pemCert = X509Certificate2.CreateFromPemFile(certPath, keyPath);

            // Windows: re-import via PFX round-trip so the private key is associated
            // with a key container HttpClient can use during the TLS handshake.
            var pfxBytes = pemCert.Export(X509ContentType.Pfx);
            try
            {
                var cert = X509CertificateLoader.LoadPkcs12(pfxBytes, password: null);
                Log.Information("mTLS enabled via PEM files: {Path}", certPath);
                return cert;
            }
            finally
            {
                Array.Clear(pfxBytes);
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to load client certificate from PEM files: {Path}", certPath);
            return null;
        }
    }

    /// <summary>
    /// Loads a client certificate from the Windows Certificate Store by thumbprint
    /// (most specific) or subject name.
    /// </summary>
    private static X509Certificate2? LoadFromCertStore(AuthConfig authConfig)
    {
        try
        {
            var storeLocation = authConfig.CertificateStoreLocation?.ToLower() switch
            {
                "currentuser" => StoreLocation.CurrentUser,
                _ => StoreLocation.LocalMachine
            };

            var storeName = authConfig.CertificateStoreName?.ToLower() switch
            {
                "root" => StoreName.Root,
                "trustedpeople" => StoreName.TrustedPeople,
                "trustedpublisher" => StoreName.TrustedPublisher,
                _ => StoreName.My
            };

            using var store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection? certs;

            // Try to find by thumbprint first (most specific)
            if (!string.IsNullOrWhiteSpace(authConfig.CertificateThumbprint))
            {
                var thumbprint = authConfig.CertificateThumbprint.Replace(" ", "").ToUpperInvariant();
                certs = store.Certificates.Find(
                    X509FindType.FindByThumbprint,
                    thumbprint,
                    validOnly: false);

                if (certs.Count > 0)
                {
                    Log.Information("mTLS enabled via Cert Store (thumbprint {Thumbprint})", thumbprint);
                    return certs[0];
                }

                Log.Warning("No certificate found with thumbprint: {Thumbprint}", thumbprint);
            }

            // Try to find by subject name
            if (!string.IsNullOrWhiteSpace(authConfig.CertificateSubject))
            {
                certs = store.Certificates.Find(
                    X509FindType.FindBySubjectName,
                    authConfig.CertificateSubject,
                    validOnly: true);

                if (certs.Count > 0)
                {
                    // Return the certificate with the latest expiration date
                    var cert = certs
                        .Cast<X509Certificate2>()
                        .Where(c => c.HasPrivateKey)
                        .OrderByDescending(c => c.NotAfter)
                        .FirstOrDefault();

                    if (cert != null)
                    {
                        Log.Information(
                            "mTLS enabled via Cert Store (subject {Subject}, expires {Expiry})",
                            cert.Subject, cert.NotAfter);
                        return cert;
                    }
                }

                Log.Warning("No valid certificate found with subject: {Subject}",
                    authConfig.CertificateSubject);
            }

            return null;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to retrieve client certificate from store");
            return null;
        }
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
                
                // Handle authentication errors - don't retry these
                if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    Log.Error("Authentication failed (401): {Error}", errorContent);
                    throw new CryptServerAuthException("API key required. Add 'auth.api_key' to config.yaml or set CRYPT_API_KEY environment variable.", 401);
                }
                
                if (response.StatusCode == System.Net.HttpStatusCode.Forbidden)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    Log.Error("Access forbidden (403): {Error}", errorContent);
                    throw new CryptServerAuthException("Invalid API key. Check your auth.api_key configuration.", 403);
                }
                
                response.EnsureSuccessStatusCode();

                var json = await response.Content.ReadAsStringAsync();
                Log.Debug("Server response: {Json}", json);

                var result = JsonSerializer.Deserialize<CheckinResponse>(json, JsonOptions);
                return result ?? new CheckinResponse();
            }
            catch (CryptServerAuthException)
            {
                throw; // Don't retry auth errors
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
            
            // Handle specific HTTP status codes
            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                Log.Error("Authentication failed: {Error}", errorContent);
                throw new CryptServerAuthException("API key required or invalid. Check your auth configuration.", (int)response.StatusCode);
            }
            
            if (response.StatusCode == System.Net.HttpStatusCode.Forbidden)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                Log.Error("Access forbidden: {Error}", errorContent);
                throw new CryptServerAuthException("Invalid API key.", (int)response.StatusCode);
            }
            
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<VerifyResponse>(json, JsonOptions);
            return result ?? new VerifyResponse();
        }
        catch (CryptServerAuthException)
        {
            throw; // Re-throw auth exceptions
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
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        TypeInfoResolver = CryptJsonContext.Default
    };

    public void Dispose()
    {
        _httpClient.Dispose();
        _clientCert?.Dispose();
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

public class CryptServerAuthException : CryptServerException
{
    public int StatusCode { get; }
    
    public CryptServerAuthException(string message, int statusCode) 
        : base(message)
    {
        StatusCode = statusCode;
    }
}

/// <summary>
/// JSON source generator for AOT/trimming compatibility.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(CheckinResponse))]
[JsonSerializable(typeof(VerifyResponse))]
internal partial class CryptJsonContext : JsonSerializerContext
{
}

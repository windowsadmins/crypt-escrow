using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CryptEscrow.Tests.Fixtures;

/// <summary>
/// Generates ephemeral RSA self-signed client certificates and serializes them
/// to PEM + key files or password-protected PFX files in a unique temp
/// directory. On dispose, deletes the temp directory.
/// </summary>
internal sealed class SelfSignedCertFactory : IDisposable
{
    private readonly string _dir;

    public SelfSignedCertFactory()
    {
        _dir = Path.Combine(Path.GetTempPath(), "crypt-escrow-tests-certs", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    /// <summary>
    /// Creates a self-signed cert with the given subject and writes it as PEM
    /// (cert) and PEM (unencrypted private key) to two files. Returns the paths.
    /// </summary>
    public (string CertPath, string KeyPath, string Thumbprint) WritePemPair(string subject = "CN=crypt-escrow-test")
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

        var certPem = cert.ExportCertificatePem();
        var keyPem = rsa.ExportRSAPrivateKeyPem();

        var certPath = Path.Combine(_dir, $"{Guid.NewGuid():N}.pem");
        var keyPath = Path.Combine(_dir, $"{Guid.NewGuid():N}.key");
        File.WriteAllText(certPath, certPem);
        File.WriteAllText(keyPath, keyPem);

        return (certPath, keyPath, cert.Thumbprint);
    }

    /// <summary>
    /// Creates a self-signed cert and writes it as a password-protected PFX file.
    /// Pass <paramref name="password"/> = null for an unprotected PFX.
    /// </summary>
    public (string PfxPath, string Thumbprint) WritePfx(string? password, string subject = "CN=crypt-escrow-test-pfx")
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

        var pfxBytes = cert.Export(X509ContentType.Pfx, password);
        var pfxPath = Path.Combine(_dir, $"{Guid.NewGuid():N}.pfx");
        File.WriteAllBytes(pfxPath, pfxBytes);

        return (pfxPath, cert.Thumbprint);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_dir))
                Directory.Delete(_dir, recursive: true);
        }
        catch
        {
            // Best-effort cleanup.
        }
    }
}

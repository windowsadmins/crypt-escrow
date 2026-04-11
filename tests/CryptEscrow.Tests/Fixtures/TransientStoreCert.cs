using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CryptEscrow.Tests.Fixtures;

/// <summary>
/// Installs a newly-generated self-signed RSA certificate into
/// <c>CurrentUser\My</c> and removes it on dispose. Uses CurrentUser (not
/// LocalMachine) so the test doesn't require admin rights. Performs a PFX
/// round-trip so the private key is associated with a persisted key container
/// that <see cref="X509Store"/> keeps alive after disposal of the source cert.
/// </summary>
internal sealed class TransientStoreCert : IDisposable
{
    public string Thumbprint { get; }
    public string Subject { get; }

    public TransientStoreCert(string subject = "CN=crypt-escrow-store-test")
    {
        Subject = subject;

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var ephemeral = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));

        var pfxBytes = ephemeral.Export(X509ContentType.Pfx);
        try
        {
            // PersistKeySet so the private key container stays on disk after
            // this process ends; MachineKeySet: false (default) keeps it in
            // CurrentUser scope so no admin is needed.
            using var persisted = X509CertificateLoader.LoadPkcs12(
                pfxBytes,
                password: null,
                keyStorageFlags: X509KeyStorageFlags.PersistKeySet);

            Thumbprint = persisted.Thumbprint;

            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            store.Add(persisted);
        }
        finally
        {
            Array.Clear(pfxBytes);
        }
    }

    public void Dispose()
    {
        try
        {
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            var found = store.Certificates.Find(
                X509FindType.FindByThumbprint, Thumbprint, validOnly: false);
            foreach (var cert in found)
            {
                store.Remove(cert);
                cert.Dispose();
            }
        }
        catch
        {
            // Best-effort cleanup; don't fail tests during teardown.
        }
    }
}

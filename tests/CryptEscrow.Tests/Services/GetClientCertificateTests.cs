using CryptEscrow.Services;
using CryptEscrow.Tests.Fixtures;
using FluentAssertions;
using Xunit;

namespace CryptEscrow.Tests.Services;

/// <summary>
/// Covers <see cref="CryptServerClient.GetClientCertificate"/> strategy priority
/// ordering (PFX+CredMgr &gt; PEM+key &gt; Cert Store by thumbprint &gt; Cert
/// Store by subject) and graceful fall-through on missing files.
/// </summary>
public class GetClientCertificateTests
{
    [Fact]
    public void ReturnsNullWhenNoStrategyConfigured()
    {
        var cfg = new AuthConfig();

        using var cert = CryptServerClient.GetClientCertificate(cfg);

        cert.Should().BeNull();
    }

    [Fact]
    public void LoadsFromPemFilesWhenOnlyPemConfigured()
    {
        using var certs = new SelfSignedCertFactory();
        var (certPath, keyPath, thumbprint) = certs.WritePemPair();

        var cfg = new AuthConfig
        {
            ClientCertPath = certPath,
            ClientKeyPath = keyPath,
        };

        using var cert = CryptServerClient.GetClientCertificate(cfg);

        cert.Should().NotBeNull();
        cert!.Thumbprint.Should().Be(thumbprint);
        cert.HasPrivateKey.Should().BeTrue();
    }

    [Fact]
    public void LoadsFromPfxWhenBothPfxAndPemConfigured_PfxWins()
    {
        using var certs = new SelfSignedCertFactory();
        var target = $"CryptEscrowTest-{Guid.NewGuid():N}";
        using var _ = new CredentialManagerWriter.Scoped(target, "pfx-pass");
        var (pfxPath, pfxThumbprint) = certs.WritePfx("pfx-pass");
        var (pemPath, keyPath, _) = certs.WritePemPair();

        var cfg = new AuthConfig
        {
            PfxPath = pfxPath,
            PfxPasswordCredential = target,
            ClientCertPath = pemPath,
            ClientKeyPath = keyPath,
        };

        using var cert = CryptServerClient.GetClientCertificate(cfg);

        cert.Should().NotBeNull();
        cert!.Thumbprint.Should().Be(pfxThumbprint, "PFX strategy is higher priority than PEM");
    }

    [Fact]
    public void LoadsUnprotectedPfxWhenNoCredentialConfigured()
    {
        using var certs = new SelfSignedCertFactory();
        var (pfxPath, thumbprint) = certs.WritePfx(password: null);

        var cfg = new AuthConfig { PfxPath = pfxPath };

        using var cert = CryptServerClient.GetClientCertificate(cfg);

        cert.Should().NotBeNull();
        cert!.Thumbprint.Should().Be(thumbprint);
    }

    [Fact]
    public void PfxWithMissingCredentialFallsThroughToPem()
    {
        using var certs = new SelfSignedCertFactory();
        var (pfxPath, _) = certs.WritePfx("pfx-pass");
        var (pemPath, keyPath, pemThumbprint) = certs.WritePemPair();

        var cfg = new AuthConfig
        {
            PfxPath = pfxPath,
            PfxPasswordCredential = $"CryptEscrowTest-DoesNotExist-{Guid.NewGuid():N}",
            ClientCertPath = pemPath,
            ClientKeyPath = keyPath,
        };

        using var cert = CryptServerClient.GetClientCertificate(cfg);

        cert.Should().NotBeNull();
        cert!.Thumbprint.Should().Be(pemThumbprint,
            "a missing Credential Manager entry should fall through to the next strategy");
    }

    [Fact]
    public void MissingPfxFileFallsThroughToPem()
    {
        using var certs = new SelfSignedCertFactory();
        var (pemPath, keyPath, pemThumbprint) = certs.WritePemPair();

        var cfg = new AuthConfig
        {
            PfxPath = @"C:\nonexistent\client.pfx",
            ClientCertPath = pemPath,
            ClientKeyPath = keyPath,
        };

        using var cert = CryptServerClient.GetClientCertificate(cfg);

        cert.Should().NotBeNull();
        cert!.Thumbprint.Should().Be(pemThumbprint);
    }

    [Fact]
    public void MissingPemFileReturnsNullWhenStoreIsEmpty()
    {
        var cfg = new AuthConfig
        {
            ClientCertPath = @"C:\nonexistent\cert.pem",
            ClientKeyPath = @"C:\nonexistent\cert.key",
        };

        using var cert = CryptServerClient.GetClientCertificate(cfg);

        cert.Should().BeNull();
    }

    [Fact]
    public void MissingPemKeyFileReturnsNullWhenStoreIsEmpty()
    {
        using var certs = new SelfSignedCertFactory();
        var (certPath, _, _) = certs.WritePemPair();

        var cfg = new AuthConfig
        {
            ClientCertPath = certPath,
            ClientKeyPath = @"C:\nonexistent\cert.key",
        };

        using var cert = CryptServerClient.GetClientCertificate(cfg);

        cert.Should().BeNull();
    }
}

using CryptEscrow.Services;
using CryptEscrow.Tests.Fixtures;
using FluentAssertions;
using Xunit;

namespace CryptEscrow.Tests.Services;

/// <summary>
/// Covers <see cref="CredentialManager.ReadGenericPassword"/>. Tests write
/// ephemeral entries via <see cref="CredentialManagerWriter.Scoped"/> and rely
/// on its dispose to clean up.
/// </summary>
public class CredentialManagerTests
{
    [Fact]
    public void ReadGenericPassword_RoundTripsAsciiPassword()
    {
        var target = $"CryptEscrowTest-{Guid.NewGuid():N}";
        using var _ = new CredentialManagerWriter.Scoped(target, "hunter2");

        CredentialManager.ReadGenericPassword(target).Should().Be("hunter2");
    }

    [Fact]
    public void ReadGenericPassword_RoundTripsUnicodePassword()
    {
        var target = $"CryptEscrowTest-{Guid.NewGuid():N}";
        const string unicodePassword = "p\u00e4ssw\u00f6rd-\u03c0-\u6f22";
        using var _ = new CredentialManagerWriter.Scoped(target, unicodePassword);

        CredentialManager.ReadGenericPassword(target).Should().Be(unicodePassword);
    }

    [Fact]
    public void ReadGenericPassword_ReturnsNullForMissingTarget()
    {
        var target = $"CryptEscrowTest-DoesNotExist-{Guid.NewGuid():N}";

        CredentialManager.ReadGenericPassword(target).Should().BeNull();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ReadGenericPassword_ReturnsNullForEmptyTarget(string? target)
    {
        CredentialManager.ReadGenericPassword(target!).Should().BeNull();
    }
}

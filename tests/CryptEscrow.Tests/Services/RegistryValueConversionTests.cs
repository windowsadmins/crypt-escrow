using CryptEscrow.Services;
using CryptEscrow.Tests.Fixtures;
using FluentAssertions;
using Microsoft.Win32;
using Xunit;

namespace CryptEscrow.Tests.Services;

/// <summary>
/// Regression coverage for issue #4: <see cref="ConfigService.GetRegistryValue"/>
/// was reading raw values with <c>as string</c>, silently dropping <c>REG_DWORD</c>
/// and <c>REG_QWORD</c> policy values. This broke every CSP-deployed boolean and
/// integer policy because Intune emits those as DWORDs.
///
/// <see cref="ConfigService.ConvertToConfigString"/> is now the single source of
/// truth for raw-value → config-string conversion, used by both the production
/// HKLM code path and the test fixtures.
/// </summary>
[Collection(GlobalStateCollection.Name)]
public class RegistryValueConversionTests
{
    // ----------------------- Pure unit tests on ConvertToConfigString -----

    [Fact]
    public void ConvertToConfigString_Null_ReturnsNull() =>
        ConfigService.ConvertToConfigString(null).Should().BeNull();

    [Fact]
    public void ConvertToConfigString_String_ReturnsAsIs() =>
        ConfigService.ConvertToConfigString("hello").Should().Be("hello");

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\n")]
    public void ConvertToConfigString_EmptyOrWhitespaceString_ReturnsNull(string input) =>
        ConfigService.ConvertToConfigString(input).Should().BeNull();

    [Theory]
    [InlineData(0, "0")]
    [InlineData(1, "1")]
    [InlineData(-1, "-1")]
    [InlineData(int.MaxValue, "2147483647")]
    [InlineData(int.MinValue, "-2147483648")]
    public void ConvertToConfigString_IntDword_ReturnsInvariantString(int value, string expected) =>
        ConfigService.ConvertToConfigString(value).Should().Be(expected);

    [Theory]
    [InlineData(0L, "0")]
    [InlineData(9999999999L, "9999999999")]
    [InlineData(long.MaxValue, "9223372036854775807")]
    public void ConvertToConfigString_LongQword_ReturnsInvariantString(long value, string expected) =>
        ConfigService.ConvertToConfigString(value).Should().Be(expected);

    [Fact]
    public void ConvertToConfigString_ByteArray_ReturnsNull() =>
        ConfigService.ConvertToConfigString(new byte[] { 1, 2, 3 }).Should().BeNull();

    [Fact]
    public void ConvertToConfigString_StringArray_ReturnsNull() =>
        ConfigService.ConvertToConfigString(new[] { "a", "b" }).Should().BeNull();

    // ----------------------- Integration tests: real registry DWORD/QWORD --

    [Fact]
    public void ConvertToConfigString_RoundTripsActualRegistryDword()
    {
        using var tempKey = new TempRegistryKey();
        tempKey.SetDword("UseMtls", 1);

        using var key = tempKey.OpenKey();
        var raw = key.GetValue("UseMtls");

        raw.Should().BeOfType<int>("Registry should return REG_DWORD as boxed int");
        ConfigService.ConvertToConfigString(raw).Should().Be("1");
    }

    [Fact]
    public void ConvertToConfigString_RoundTripsActualRegistryQword()
    {
        using var tempKey = new TempRegistryKey();
        tempKey.SetQword("SomeQword", 42L);

        using var key = tempKey.OpenKey();
        var raw = key.GetValue("SomeQword");

        raw.Should().BeOfType<long>("Registry should return REG_QWORD as boxed long");
        ConfigService.ConvertToConfigString(raw).Should().Be("42");
    }

    [Fact]
    public void ConvertToConfigString_RoundTripsActualRegistryString()
    {
        using var tempKey = new TempRegistryKey();
        tempKey.SetString("ServerUrl", "https://crypt.example.com");

        using var key = tempKey.OpenKey();
        var raw = key.GetValue("ServerUrl");

        ConfigService.ConvertToConfigString(raw).Should().Be("https://crypt.example.com");
    }

    // ----------------------- End-to-end: DWORD policy → GetRegistryBool/Int --

    [Fact]
    public void GetSkipCertCheck_ReadsRegistryDwordOne()
    {
        using var env = new EnvironmentSnapshot("CRYPT_ESCROW_SKIP_CERT_CHECK");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        reg.SetDword("SkipCertCheck", 1);

        ConfigService.GetSkipCertCheck().Should().BeTrue();
    }

    [Fact]
    public void GetSkipCertCheck_ReadsRegistryDwordZero()
    {
        using var env = new EnvironmentSnapshot("CRYPT_ESCROW_SKIP_CERT_CHECK");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        reg.SetDword("SkipCertCheck", 0);

        ConfigService.GetSkipCertCheck().Should().BeFalse();
    }

    [Fact]
    public void GetKeyEscrowIntervalHours_ReadsRegistryDword()
    {
        using var env = new EnvironmentSnapshot("CRYPT_KEY_ESCROW_INTERVAL");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        reg.SetDword("KeyEscrowIntervalHours", 6);

        ConfigService.GetKeyEscrowIntervalHours().Should().Be(6);
    }

    [Fact]
    public void GetAutoRotate_ReadsRegistryDwordOne()
    {
        using var env = new EnvironmentSnapshot("CRYPT_ESCROW_AUTO_ROTATE");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        reg.SetDword("AutoRotate", 1);

        ConfigService.GetAutoRotate().Should().BeTrue();
    }
}

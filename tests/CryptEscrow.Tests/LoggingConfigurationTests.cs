using System;
using System.IO;
using CryptEscrow;
using Serilog.Events;
using Xunit;

namespace CryptEscrow.Tests;

/// <summary>
/// Where the log goes and what it records.
/// </summary>
/// <remarks>
/// The regression these pin down: the log path was hardcoded to a ProgramData root of
/// its own, while the installer wrote a config pointing somewhere else and the
/// troubleshooting docs quoted that other path. The configured value was never read --
/// the property was named Path, so the "file_path" key bound to nothing.
/// </remarks>
public class LoggingConfigurationTests
{
    [Fact]
    public void DefaultsUnderManagedEncryptionWithTheRestOfTheTool()
    {
        var expected = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "ManagedEncryption", "logs", "crypt.log");

        Assert.Equal(expected, Program.ResolveLogPath(null));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void BlankConfiguredPathFallsBackToTheDefault(string configured)
    {
        Assert.Equal(Program.ResolveLogPath(null), Program.ResolveLogPath(configured));
    }

    [Fact]
    public void ConfiguredPathIsHonoured()
    {
        var configured = Path.Combine("D:", "logs", "crypt.log");

        Assert.Equal(configured, Program.ResolveLogPath(configured));
    }

    [Theory]
    [InlineData("Verbose", LogEventLevel.Verbose)]
    [InlineData("debug", LogEventLevel.Debug)]
    [InlineData("INFO", LogEventLevel.Information)]
    [InlineData("Information", LogEventLevel.Information)]
    [InlineData("warn", LogEventLevel.Warning)]
    [InlineData("WARNING", LogEventLevel.Warning)]
    [InlineData("Error", LogEventLevel.Error)]
    [InlineData("fatal", LogEventLevel.Fatal)]
    public void LevelNamesMapOntoSerilog(string configured, LogEventLevel expected)
    {
        Assert.Equal(expected, Program.ParseLevel(configured));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("nonsense")]
    public void UnrecognisedLevelStaysAtInformationRatherThanSilencingTheLog(string? configured)
    {
        Assert.Equal(LogEventLevel.Information, Program.ParseLevel(configured));
    }
}

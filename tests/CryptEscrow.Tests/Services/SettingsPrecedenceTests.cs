using CryptEscrow.Services;
using CryptEscrow.Tests.Fixtures;
using FluentAssertions;
using Xunit;

namespace CryptEscrow.Tests.Services;

/// <summary>
/// The full chain, highest first: command line, policy, machine settings, environment,
/// legacy config file, default. Each test sets every layer at or below the one it
/// expects to win, so a layer that is skipped or misordered fails it.
/// </summary>
[Collection(GlobalStateCollection.Name)]
public class SettingsPrecedenceTests
{
    private const string UrlEnv = "CRYPT_ESCROW_SERVER_URL";
    private const string SkipEnv = "CRYPT_ESCROW_SKIP_CERT_CHECK";
    private const string IntervalEnv = "CRYPT_KEY_ESCROW_INTERVAL";

    private static void SetAllUrlLayers(EnvironmentSnapshot env, TempRegistryKey reg, TempConfigFile yaml)
    {
        reg.SetString("ServerUrl", "https://policy.example.com");
        reg.SetSetting("ServerUrl", "https://settings.example.com");
        env.Set(UrlEnv, "https://env.example.com");
        yaml.WriteYaml("server:\n  url: https://file.example.com\n");
    }

    [Fact]
    public void CommandLineBeatsEveryLayer()
    {
        using var env = new EnvironmentSnapshot(UrlEnv);
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        SetAllUrlLayers(env, reg, yaml);

        ConfigService.ResolveServerUrl("https://cli.example.com")
            .Should().Be(new Resolved<string?>("https://cli.example.com", SettingSource.CommandLine));
    }

    [Fact]
    public void PolicyBeatsSettingsEnvironmentAndFile()
    {
        using var env = new EnvironmentSnapshot(UrlEnv);
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        SetAllUrlLayers(env, reg, yaml);

        ConfigService.ResolveServerUrl()
            .Should().Be(new Resolved<string?>("https://policy.example.com", SettingSource.Policy));
    }

    [Fact]
    public void SettingsBeatEnvironmentAndFile()
    {
        using var env = new EnvironmentSnapshot(UrlEnv);
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        reg.SetSetting("ServerUrl", "https://settings.example.com");
        env.Set(UrlEnv, "https://env.example.com");
        yaml.WriteYaml("server:\n  url: https://file.example.com\n");

        ConfigService.ResolveServerUrl()
            .Should().Be(new Resolved<string?>("https://settings.example.com", SettingSource.MachineSettings));
    }

    [Fact]
    public void EnvironmentBeatsFile()
    {
        using var env = new EnvironmentSnapshot(UrlEnv);
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        env.Set(UrlEnv, "https://env.example.com");
        yaml.WriteYaml("server:\n  url: https://file.example.com\n");

        ConfigService.ResolveServerUrl()
            .Should().Be(new Resolved<string?>("https://env.example.com", SettingSource.Environment));
    }

    [Fact]
    public void FileBeatsDefault()
    {
        using var env = new EnvironmentSnapshot(UrlEnv);
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        yaml.WriteYaml("server:\n  url: https://file.example.com\n");

        ConfigService.ResolveServerUrl()
            .Should().Be(new Resolved<string?>("https://file.example.com", SettingSource.LegacyFile));
    }

    [Fact]
    public void DefaultWhenNothingIsSet()
    {
        using var env = new EnvironmentSnapshot(UrlEnv);
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        ConfigService.ResolveServerUrl().Should().Be(new Resolved<string?>(null, SettingSource.Default));
    }

    [Fact]
    public void EnvironmentCannotTurnOffCertificateChecksThatPolicyRequires()
    {
        using var env = new EnvironmentSnapshot(SkipEnv);
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        reg.SetDword("SkipCertCheck", 0);
        env.Set(SkipEnv, "true");

        ConfigService.ResolveSkipCertCheck()
            .Should().Be(new Resolved<bool>(false, SettingSource.Policy));
    }

    [Fact]
    public void SkipCertCheckFlagStillAppliesToThisRun()
    {
        using var env = new EnvironmentSnapshot(SkipEnv);
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        reg.SetDword("SkipCertCheck", 0);

        ConfigService.ResolveSkipCertCheck(cliOverride: true)
            .Should().Be(new Resolved<bool>(true, SettingSource.CommandLine));
    }

    [Fact]
    public void BoolSettingsDwordBeatsEnvironment()
    {
        using var env = new EnvironmentSnapshot(SkipEnv);
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        reg.SetSettingDword("SkipCertCheck", 0);
        env.Set(SkipEnv, "true");

        ConfigService.ResolveSkipCertCheck()
            .Should().Be(new Resolved<bool>(false, SettingSource.MachineSettings));
    }

    [Fact]
    public void UnparseablePolicyFallsThroughToNextLayer()
    {
        using var env = new EnvironmentSnapshot(IntervalEnv);
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        reg.SetString("KeyEscrowIntervalHours", "not-a-number");
        reg.SetSetting("KeyEscrowIntervalHours", "12");

        ConfigService.ResolveKeyEscrowIntervalHours()
            .Should().Be(new Resolved<int>(12, SettingSource.MachineSettings));
    }

    [Fact]
    public void IntFallsBackToFileThenDefault()
    {
        using var env = new EnvironmentSnapshot(IntervalEnv);
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        ConfigService.ResolveKeyEscrowIntervalHours().Should().Be(new Resolved<int>(1, SettingSource.Default));

        yaml.WriteYaml("escrow:\n  key_escrow_interval_hours: 24\n");
        ConfigService.ResolveKeyEscrowIntervalHours().Should().Be(new Resolved<int>(24, SettingSource.LegacyFile));
    }

    [Fact]
    public void LoggingSettingsCanBeSetByPolicy()
    {
        using var env = new EnvironmentSnapshot("CRYPT_LOG_LEVEL", "CRYPT_LOG_FILE_PATH", "CRYPT_LOG_RETAINED_DAYS");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        yaml.WriteYaml("logging:\n  level: DEBUG\n  file_path: C:\\file\\crypt.log\n  retained_days: 5\n");
        reg.SetString("LogLevel", "WARN");
        reg.SetString("LogFilePath", @"C:\policy\crypt.log");
        reg.SetDword("LogRetainedDays", 90);

        var logging = ConfigService.GetLoggingConfig();

        logging.Level.Should().Be("WARN");
        logging.FilePath.Should().Be(@"C:\policy\crypt.log");
        logging.RetainedDays.Should().Be(90);
    }

    [Fact]
    public void CertificateStoreCanBeSetByPolicy()
    {
        using var env = new EnvironmentSnapshot("CRYPT_CERT_STORE_LOCATION", "CRYPT_CERT_STORE_NAME");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        reg.SetString("CertificateStoreLocation", "CurrentUser");
        reg.SetString("CertificateStoreName", "Root");

        var auth = ConfigService.GetAuthConfig();

        auth.CertificateStoreLocation.Should().Be("CurrentUser");
        auth.CertificateStoreName.Should().Be("Root");
    }

    [Fact]
    public void EverySettableKeyHasAPolicyNameThatDescribeReports()
    {
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        var described = ConfigService.Describe().Select(d => d.Name).ToHashSet();

        described.Should().BeEquivalentTo(ConfigService.SettableKeys.Values.ToHashSet());
    }

    // ------------------------------------------------------ untrusted file

    [Fact]
    public void UntrustedConfigFileIsIgnoredAndRecorded()
    {
        using var env = new EnvironmentSnapshot(UrlEnv);
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        yaml.WriteYaml("server:\n  url: https://file.example.com\n");
        yaml.MarkUntrusted("can be modified by S-1-5-32-545");

        ConfigService.ResolveServerUrl().Should().Be(new Resolved<string?>(null, SettingSource.Default));
        ConfigService.LoadConfig().Should().BeNull();
        ConfigService.IgnoredFileNotes.Should().ContainSingle()
            .Which.Should().Contain("config file").And.Contain("S-1-5-32-545");
    }

    [Fact]
    public void UntrustedTimestampDoesNotSuppressEscrow()
    {
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        File.WriteAllText(Path.Combine(Path.GetDirectoryName(yaml.FilePath)!, "last_escrow.txt"),
            DateTimeOffset.UtcNow.AddYears(1).ToString("o"));

        ConfigService.ShouldEscrowNow().Should().BeFalse("a trusted timestamp in the future defers escrow");

        yaml.MarkUntrusted("owned by a standard user");
        ConfigService.GetLastEscrowTimestamp().Should().BeNull();
        ConfigService.ShouldEscrowNow().Should().BeTrue();
    }

    // -------------------------------------------------------- config set

    [Theory]
    [InlineData("server.url", "https://set.example.com", "ServerUrl", "https://set.example.com")]
    [InlineData("ServerUrl", "https://set.example.com", "ServerUrl", "https://set.example.com")]
    [InlineData("escrow.auto_rotate", "1", "AutoRotate", "true")]
    [InlineData("server.verify_ssl", "false", "SkipCertCheck", "true")]
    [InlineData("logging.retained_days", "14", "LogRetainedDays", "14")]
    public void SetValueWritesMachineSettings(string key, string value, string valueName, string stored)
    {
        using var reg = new TempRegistryKey();

        ConfigService.SetValue(key, value);

        reg.GetSetting(valueName).Should().Be(stored);
    }

    [Theory]
    [InlineData("server.nope", "x")]
    [InlineData("escrow.auto_rotate", "maybe")]
    [InlineData("escrow.key_escrow_interval_hours", "soon")]
    public void SetValueRejectsUnknownKeysAndBadValues(string key, string value)
    {
        using var reg = new TempRegistryKey();

        var act = () => ConfigService.SetValue(key, value);

        act.Should().Throw<ArgumentException>();
    }
}

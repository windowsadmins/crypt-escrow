using System.ComponentModel;
using CryptEscrow.Gui;
using CryptEscrow.Services;
using CryptEscrow.Tests.Fixtures;
using CryptEscrow.Tests.Services;
using FluentAssertions;
using Xunit;

namespace CryptEscrow.Tests.Gui;

public class PrefsElevationTests
{
    [Theory]
    [InlineData(true, false, true)]
    [InlineData(true, true, false)]
    [InlineData(false, false, false)]
    [InlineData(false, true, false)]
    public void EditableOnlyWhenElevatedAndNotManaged(bool elevated, bool managed, bool expected) =>
        PrefsElevation.CanEdit(elevated, managed).Should().Be(expected);

    [Fact]
    public void RelaunchAsksForElevationAndOpensOnPrefs()
    {
        var start = PrefsElevation.BuildElevatedRelaunch(@"C:\Program Files\Crypt\Managed Encryption Escrow.exe");

        start.Verb.Should().Be("runas");
        start.UseShellExecute.Should().BeTrue();
        PrefsElevation.OpensOnPrefs(start.ArgumentList).Should().BeTrue();
    }

    [Fact]
    public void CancelledUacPromptIsRecognised()
    {
        PrefsElevation.IsElevationCancelled(new Win32Exception(1223)).Should().BeTrue();
        PrefsElevation.IsElevationCancelled(new Win32Exception(5)).Should().BeFalse();
    }
}

public class RunModesTests
{
    [Fact]
    public void ModesMapToCliCommands()
    {
        RunModes.Arguments(RunMode.EscrowNow, cleanupOldProtectors: true).Should().Equal("escrow", "--force");
        RunModes.Arguments(RunMode.Verify, cleanupOldProtectors: true).Should().Equal("verify");
    }

    [Theory]
    [InlineData(true, "true")]
    [InlineData(false, "false")]
    public void RotationPassesTheCleanupSetting(bool cleanup, string expected) =>
        RunModes.Arguments(RunMode.RotateKey, cleanup).Should().Equal("rotate", "--cleanup", expected);

    [Fact]
    public void NoModeRegistersTasksOrChangesSettings() =>
        RunModes.All.SelectMany(m => RunModes.Arguments(m, true))
            .Should().NotContain(["register-task", "config", "set", "--server", "--skip-cert-check"]);

    [Fact]
    public void OnlyRotationAsksFirst() =>
        RunModes.All.Where(RunModes.NeedsConfirmation).Should().Equal(RunMode.RotateKey);
}

public class RecoveryKeyRedactorTests
{
    private const string Key = "123456-234567-345678-456789-567890-678901-789012-890123";

    [Theory]
    [InlineData("Recovery password: " + Key)]
    [InlineData("{\"recovery_password\":\"" + Key + "\"}")]
    [InlineData("123456234567345678456789567890678901789012890123")]
    public void RecoveryPasswordsAreRemoved(string line)
    {
        var redacted = RecoveryKeyRedactor.Redact(line);

        redacted.Should().Contain(RecoveryKeyRedactor.Replacement);
        redacted.Should().NotContainAny("123456", "890123");
    }

    [Theory]
    [InlineData("[2026-10-06 09:31:15] INFO  Created protector: {0E2C5D3B-1A9F-4C2B-8F1D-3E4A5B6C7D8E}")]
    [InlineData("Serial 5CD1234567, interval 24 hours")]
    [InlineData("123456-234567")]
    public void OrdinaryLinesAreUntouched(string line) =>
        RecoveryKeyRedactor.Redact(line).Should().Be(line);
}

public class LogSessionsTests
{
    [Theory]
    [InlineData("[2026-10-06 09:31:15] ERROR Escrow failed", LogLineLevel.Error)]
    [InlineData("[2026-10-06 09:31:15] WARN  Ignoring config file", LogLineLevel.Warning)]
    [InlineData("[2026-10-06 09:31:15] INFO  Key escrowed", LogLineLevel.Info)]
    [InlineData("[2026-10-06 09:31:15] DEBUG Server response", LogLineLevel.Debug)]
    [InlineData("[09:31:15] [WRN] Ignoring config file", LogLineLevel.Warning)]
    [InlineData("[09:31:15] [ERR] Failed", LogLineLevel.Error)]
    [InlineData("[09:31:15] [DBG] detail", LogLineLevel.Debug)]
    [InlineData("   at CryptEscrow.Program.Main()", LogLineLevel.Default)]
    [InlineData("[2026-10-06 09:31:15] INFORMATIONAL", LogLineLevel.Default)]
    public void ClassifiesFileAndConsoleLines(string line, LogLineLevel expected) =>
        LogSessions.Classify(line).Should().Be(expected);

    [Fact]
    public void ListsDaySessionsNewestFirstAndSkipsTheEventStream()
    {
        var root = Path.Combine(Path.GetTempPath(), "crypt-escrow-tests", Guid.NewGuid().ToString("N"));
        try
        {
            foreach (var day in new[] { "2026-10-04", "2026-10-06", "2026-10-05" })
            {
                Directory.CreateDirectory(Path.Combine(root, day));
                File.WriteAllText(Path.Combine(root, day, LogLayout.DefaultFileName), "x");
                File.WriteAllText(Path.Combine(root, day, LogLayout.EventsFileName), "{}");
            }
            Directory.CreateDirectory(Path.Combine(root, "not-a-day"));
            File.WriteAllText(Path.Combine(root, "not-a-day", "other.log"), "x");
            File.WriteAllText(Path.Combine(root, "CryptEscrow_20260301.log"), "legacy");
            File.SetLastWriteTime(Path.Combine(root, "CryptEscrow_20260301.log"), new DateTime(2026, 3, 1));

            var sessions = LogSessions.List(root);

            sessions.Select(s => s.Name).Should().Equal("2026-10-06", "2026-10-05", "2026-10-04", "CryptEscrow_20260301.log");
            sessions.Should().OnlyContain(s => s.Path.EndsWith(".log"));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void MissingFolderListsNothing() =>
        LogSessions.List(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"))).Should().BeEmpty();

    [Fact]
    public void ReadsALogThatIsStillOpenForWriting()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".log");
        try
        {
            using var writer = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
            writer.Write("line\n"u8);
            writer.Flush();

            LogSessions.ReadShared(path).Should().Be("line\n");
        }
        finally
        {
            File.Delete(path);
        }
    }
}

[Collection(GlobalStateCollection.Name)]
public class SettingsCatalogTests
{
    [Fact]
    public void PrefsShowsEverySettingTheCliReads() =>
        SettingsCatalog.Definitions.Select(d => d.Name)
            .Should().BeEquivalentTo(ConfigService.SettableKeys.Values);

    [Fact]
    public void EveryDefinitionIsInAKnownCard() =>
        SettingsCatalog.Definitions.Should().OnlyContain(d => SettingsCatalog.Groups.Contains(d.Group));

    [Fact]
    public void PolicyValueIsShownAndLocked()
    {
        using var env = new EnvironmentSnapshot("CRYPT_ESCROW_SERVER_URL");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        reg.SetString("ServerUrl", "https://policy.example.com");
        reg.SetSetting("ServerUrl", "https://settings.example.com");

        var state = SettingsCatalog.Load().Single(s => s.Definition.Name == "ServerUrl");

        state.IsManaged.Should().BeTrue();
        state.FieldValue.Should().Be("https://policy.example.com");
        PrefsElevation.CanEdit(isElevated: true, state.IsManaged).Should().BeFalse();
    }

    [Fact]
    public void UnmanagedFieldShowsTheMachineSettingAndWhereTheValueComesFrom()
    {
        using var env = new EnvironmentSnapshot("CRYPT_KEY_ESCROW_INTERVAL");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        var interval = SettingsCatalog.Load().Single(s => s.Definition.Name == "KeyEscrowIntervalHours");
        interval.FieldValue.Should().BeNull();
        interval.SourceCaption.Should().Be("Default: 1");

        reg.SetSetting("KeyEscrowIntervalHours", "12");
        interval = SettingsCatalog.Load().Single(s => s.Definition.Name == "KeyEscrowIntervalHours");
        interval.FieldValue.Should().Be("12");
        interval.IsManaged.Should().BeFalse();
    }

    [Fact]
    public void SecretValueNeverReachesTheField()
    {
        using var env = new EnvironmentSnapshot("CRYPT_API_KEY");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        reg.SetSetting("ApiKey", "s3cret-value");

        var apiKey = SettingsCatalog.Load().Single(s => s.Definition.Name == "ApiKey");

        apiKey.FieldValue.Should().BeNull();
        apiKey.EffectiveValue.Should().NotContain("s3cret");
        apiKey.SecretStatus(isElevated: false).Should().NotContain("Saved").And.NotContain("s3cret");
        apiKey.SecretStatus(isElevated: true).Should().Be("Saved");
    }

    [Fact]
    public void SecretSetByPolicySaysSo()
    {
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        reg.SetString("ApiKey", "from-policy");

        SettingsCatalog.Load().Single(s => s.Definition.Name == "ApiKey")
            .SecretStatus(isElevated: true).Should().Be("Saved (by policy)");
    }

    [Fact]
    public void SecretInTheProtectedStoreShowsAsSavedAfterUnlock()
    {
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        SecretStore.Write("ApiKey", "stored-value");

        var apiKey = SettingsCatalog.Load().Single(s => s.Definition.Name == "ApiKey");

        apiKey.SecretStatus(isElevated: true).Should().Be("Saved");
        apiKey.SecretStatus(isElevated: false).Should().NotContain("Saved");
        apiKey.MachineValue.Should().NotContain("stored-value");
    }

    [Fact]
    public void MigratedPolicySecretStaysManagedAndCannotBeChanged()
    {
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        reg.SetString("ApiKey", "from-policy");
        SecretStore.MigrateReadableCopies();

        var apiKey = SettingsCatalog.Load().Single(s => s.Definition.Name == "ApiKey");

        apiKey.IsManaged.Should().BeTrue();
        apiKey.SecretStatus(isElevated: true).Should().Be("Saved (by policy)");
        var save = () => SettingsCatalog.Save("ApiKey", "mine");
        save.Should().Throw<InvalidOperationException>();
        reg.GetSecret("ApiKey").Should().Be("from-policy");
    }

    [Fact]
    public void SavingAndClearingASecretUsesTheProtectedStore()
    {
        using var reg = new TempRegistryKey();

        SettingsCatalog.Save("ApiKey", "new-key");
        reg.GetSecret("ApiKey").Should().Be("new-key");
        reg.GetSetting("ApiKey").Should().BeNull();

        SettingsCatalog.Save("ApiKey", "");
        reg.GetSecret("ApiKey").Should().BeNull();
    }

    [Fact]
    public void SaveWritesAndEmptyClearsTheMachineSetting()
    {
        using var reg = new TempRegistryKey();

        SettingsCatalog.Save("ServerUrl", "  https://new.example.com ");
        reg.GetSetting("ServerUrl").Should().Be("https://new.example.com");

        SettingsCatalog.Save("ServerUrl", "");
        reg.GetSetting("ServerUrl").Should().BeNull();
    }

    [Fact]
    public void SaveRefusesAManagedSetting()
    {
        using var reg = new TempRegistryKey();
        reg.SetString("ServerUrl", "https://policy.example.com");

        var act = () => SettingsCatalog.Save("ServerUrl", "https://other.example.com");

        act.Should().Throw<InvalidOperationException>();
        reg.GetSetting("ServerUrl").Should().BeNull();
    }
}

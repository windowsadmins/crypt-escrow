using CryptEscrow.Gui;
using CryptEscrow.Tests.Fixtures;
using CryptEscrow.Tests.Services;
using FluentAssertions;
using Xunit;

namespace CryptEscrow.Tests.Gui;

[Collection(GlobalStateCollection.Name)]
public class SettingsApplyTests
{
    private static SettingDefinition Definition(string name) =>
        SettingsCatalog.Definitions.Single(d => d.Name == name);

    [Fact]
    public void PayloadRoundTripsIncludingClears()
    {
        var changes = new Dictionary<string, string?>
        {
            ["ServerUrl"] = "https://crypt.example.com/\"quoted\"",
            ["LogLevel"] = null,
            ["ApiKey"] = "  spaced secret  "
        };

        var back = SettingsApply.Deserialize(SettingsApply.Serialize(changes));

        back.Should().BeEquivalentTo(changes);
    }

    [Theory]
    [InlineData("{\"ServerUrl\": 5}")]
    [InlineData("[]")]
    [InlineData("not json")]
    public void MalformedPayloadIsRefusedWithoutWriting(string json)
    {
        using var reg = new TempRegistryKey();
        var path = Path.Combine(Path.GetTempPath(), $"crypt-escrow-test-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, json);
        try
        {
            SettingsApply.RunFromFile(path).Should().Be(SettingsApply.ExitUnreadable);
            reg.GetSetting("ServerUrl").Should().BeNull();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void WriterSkipsPolicyManagedKeysAndWritesTheRest()
    {
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        reg.SetString("ServerUrl", "https://policy.example.com");

        var result = SettingsApply.Apply(new Dictionary<string, string?>
        {
            ["ServerUrl"] = "https://mine.example.com",
            ["KeyEscrowIntervalHours"] = "6"
        });

        result.Succeeded.Should().BeTrue();
        result.SkippedManaged.Should().Equal("ServerUrl");
        result.Saved.Should().Equal("KeyEscrowIntervalHours");
        reg.GetSetting("ServerUrl").Should().BeNull();
        reg.GetSetting("KeyEscrowIntervalHours").Should().Be("6");
    }

    [Fact]
    public void ApplyModeWritesThePayloadFileAndClearsNulls()
    {
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        reg.SetSetting("PostRunCommand", "old");
        var path = SettingsApply.WritePayload(new Dictionary<string, string?>
        {
            ["ServerUrl"] = " https://new.example.com ",
            ["PostRunCommand"] = null
        });
        try
        {
            SettingsApply.RunFromFile(path).Should().Be(SettingsApply.ExitSaved);
            reg.GetSetting("ServerUrl").Should().Be("https://new.example.com");
            reg.GetSetting("PostRunCommand").Should().BeNull();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ApplyModeWritesNothingWhenAnyValueIsInvalid()
    {
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        var path = SettingsApply.WritePayload(new Dictionary<string, string?>
        {
            ["ServerUrl"] = "https://new.example.com",
            ["KeyEscrowIntervalHours"] = "-3"
        });
        try
        {
            SettingsApply.RunFromFile(path).Should().Be(SettingsApply.ExitInvalid);
            reg.GetSetting("ServerUrl").Should().BeNull();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void UnknownSettingIsAnError() =>
        SettingsApply.Apply(new Dictionary<string, string?> { ["NotASetting"] = "x" })
            .Errors.Should().ContainSingle();

    [Theory]
    [InlineData("KeyEscrowIntervalHours", "12", "12", null)]
    [InlineData("KeyEscrowIntervalHours", "-1", null, "whole number")]
    [InlineData("KeyEscrowIntervalHours", "two", null, "whole number")]
    [InlineData("SkipCertCheck", "TRUE", "true", null)]
    [InlineData("SkipCertCheck", "maybe", null, "on or off")]
    [InlineData("LogLevel", "warn", "WARN", null)]
    [InlineData("LogLevel", "LOUD", null, "one of")]
    [InlineData("ServerUrl", "  https://x.example.com ", "https://x.example.com", null)]
    [InlineData("ServerUrl", "   ", null, null)]
    public void ValuesAreCheckedWithTheTabsRules(string name, string value, string? expected, string? error)
    {
        var (saved, message) = SettingsApply.Validate(Definition(name), value);
        saved.Should().Be(expected);
        if (error is null)
            message.Should().BeNull();
        else
            message.Should().Contain(error);
    }
}

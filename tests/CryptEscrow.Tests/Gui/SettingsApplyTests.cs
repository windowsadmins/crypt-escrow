using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
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

        SettingsApply.RunFromJson(json).Should().Be(SettingsApply.ExitUnreadable);
        reg.GetSetting("ServerUrl").Should().BeNull();
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
    public async Task ApplyModeReadsTheChangesOverThePipeAndClearsNulls()
    {
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        reg.SetSetting("PostRunCommand", "old");
        var name = SettingsApply.NewPipeName();
        using var pipe = SettingsApply.CreatePipe(name);

        var child = Task.Run(() => SettingsApply.RunFromPipe(name));
        await SettingsApply.SendAsync(pipe, new Dictionary<string, string?>
        {
            ["ServerUrl"] = " https://new.example.com ",
            ["PostRunCommand"] = null
        }, new CancellationTokenSource(TimeSpan.FromSeconds(10)).Token);

        (await child).Should().Be(SettingsApply.ExitSaved);
        reg.GetSetting("ServerUrl").Should().Be("https://new.example.com");
        reg.GetSetting("PostRunCommand").Should().BeNull();
    }

    [Fact]
    public void PipeIsOpenOnlyToTheUserAdministratorsAndSystem()
    {
        using var pipe = SettingsApply.CreatePipe(SettingsApply.NewPipeName());
        using var identity = WindowsIdentity.GetCurrent();

        var allowed = pipe.GetAccessControl()
            .GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<PipeAccessRule>()
            .Where(r => r.AccessControlType == AccessControlType.Allow)
            .Select(r => r.IdentityReference.Value)
            .Distinct();

        allowed.Should().BeEquivalentTo([identity.User!.Value, "S-1-5-32-544", "S-1-5-18"]);
    }

    [Theory]
    [InlineData("crypt-escrow-settings-0123456789abcdef0123456789abcdef", true)]
    [InlineData("crypt-escrow-settings-nope", false)]
    [InlineData(@"\\.\pipe\something-else", false)]
    public void ApplyModeOnlyConnectsToItsOwnPipeNames(string name, bool expected) =>
        SettingsApply.IsPipeName(name).Should().Be(expected);

    [Fact]
    public void ApplyModeWritesNothingWhenAnyValueIsInvalid()
    {
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        SettingsApply.RunFromJson(SettingsApply.Serialize(new Dictionary<string, string?>
        {
            ["ServerUrl"] = "https://new.example.com",
            ["KeyEscrowIntervalHours"] = "-3"
        })).Should().Be(SettingsApply.ExitInvalid);

        reg.GetSetting("ServerUrl").Should().BeNull();
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

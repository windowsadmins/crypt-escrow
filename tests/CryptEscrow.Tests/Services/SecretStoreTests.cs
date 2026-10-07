using System.Security.AccessControl;
using System.Security.Principal;
using CryptEscrow.Services;
using CryptEscrow.Tests.Fixtures;
using FluentAssertions;
using Microsoft.Win32;
using Xunit;

namespace CryptEscrow.Tests.Services;

/// <summary>
/// Credentials move out of every user-readable place into the protected store, and a
/// readable copy goes only once the store holds the value.
/// </summary>
[Collection(GlobalStateCollection.Name)]
public class SecretStoreTests
{
    private const string Key = "ApiKey";

    [Fact]
    public void SettingsCopyMovesToTheStore()
    {
        using var reg = new TempRegistryKey();
        reg.SetSetting(Key, "from-settings");

        var notes = SecretStore.MigrateReadableCopies();

        reg.GetSecret(Key).Should().Be("from-settings");
        reg.GetSetting(Key).Should().BeNull();
        SecretStore.ReadSource(Key).Should().Be(SettingSource.MachineSettings);
        notes.Should().ContainSingle().Which.Should().Contain("Moved ApiKey");
    }

    [Fact]
    public void PolicyCopyMovesAndIsBlankedSoItStillShowsAsManaged()
    {
        using var reg = new TempRegistryKey();
        reg.SetString(Key, "from-policy");

        SecretStore.MigrateReadableCopies();

        reg.GetSecret(Key).Should().Be("from-policy");
        reg.GetPolicy(Key).Should().Be(string.Empty);
        ConfigService.GetPolicyValue(Key).Should().BeNull();
        SecretStore.IsSetByPolicy(Key).Should().BeTrue();
        SecretStore.ReadSource(Key).Should().Be(SettingSource.Policy);
    }

    [Fact]
    public void MdmPolicyPathIsMigratedToo()
    {
        using var reg = new TempRegistryKey();
        using (var mdm = Registry.CurrentUser.CreateSubKey(reg.PolicyMdmPath))
            mdm.SetValue(Key, "from-mdm");

        SecretStore.MigrateReadableCopies();

        reg.GetSecret(Key).Should().Be("from-mdm");
        using var check = Registry.CurrentUser.OpenSubKey(reg.PolicyMdmPath);
        check!.GetValue(Key).Should().Be(string.Empty);
    }

    [Fact]
    public void PolicyWinsWhenSeveralLayersHoldTheKey()
    {
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        yaml.WriteYaml("server:\n  auth:\n    api_key: from-file\n");
        reg.MachineEnvironment["CRYPT_API_KEY"] = "from-env";
        reg.SetSetting(Key, "from-settings");
        reg.SetString(Key, "from-policy");

        SecretStore.MigrateReadableCopies();

        reg.GetSecret(Key).Should().Be("from-policy");
        reg.GetSetting(Key).Should().BeNull();
        reg.MachineEnvironment.Should().NotContainKey("CRYPT_API_KEY");
        File.ReadAllText(yaml.FilePath).Should().NotContain("api_key");
    }

    [Fact]
    public void ALowerLayerLaterDoesNotReplaceAPolicyValue()
    {
        using var reg = new TempRegistryKey();
        reg.SetString(Key, "from-policy");
        SecretStore.MigrateReadableCopies();

        reg.SetSetting(Key, "from-settings");
        var notes = SecretStore.MigrateReadableCopies();

        reg.GetSecret(Key).Should().Be("from-policy");
        reg.GetSetting(Key).Should().BeNull("the readable copy goes even when it is not used");
        notes.Should().Contain(n => n.Contains("already holds"));
    }

    [Fact]
    public void ANewPolicyValueReplacesTheStoredOne()
    {
        using var reg = new TempRegistryKey();
        reg.SetString(Key, "first");
        SecretStore.MigrateReadableCopies();

        reg.SetString(Key, "second");
        SecretStore.MigrateReadableCopies();

        reg.GetSecret(Key).Should().Be("second");
    }

    [Fact]
    public void ConfigFileKeyMovesAndOnlyThatLineIsRemoved()
    {
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        yaml.WriteYaml("server:\n  url: https://crypt.example.com\n  auth:\n    api_key: from-file\n    api_key_header: X-Token\n");

        SecretStore.MigrateReadableCopies();

        reg.GetSecret(Key).Should().Be("from-file");
        var remaining = File.ReadAllText(yaml.FilePath);
        remaining.Should().NotContain("from-file");
        remaining.Should().Contain("url: https://crypt.example.com").And.Contain("api_key_header: X-Token");
    }

    [Fact]
    public void UntrustedConfigFileIsNeitherImportedNorEdited()
    {
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        const string content = "server:\n  auth:\n    api_key: planted\n";
        yaml.WriteYaml(content);
        yaml.MarkUntrusted("owned by a standard user");

        SecretStore.MigrateReadableCopies();

        reg.GetSecret(Key).Should().BeNull();
        File.ReadAllText(yaml.FilePath).Should().Be(content);
    }

    [Fact]
    public void ReadableCopyStaysWhenTheStoreCannotBeWritten()
    {
        using var reg = new TempRegistryKey();
        reg.SetSetting(Key, "from-settings");
        var writable = SecretStore.LocationsOverride!;
        using var readOnlyRoot = Registry.CurrentUser.OpenSubKey(reg.Root, writable: false)!;
        SecretStore.LocationsOverride = writable with
        {
            Root = readOnlyRoot,
            SecretsPath = "Secrets",
            SettingsPath = writable.SettingsPath.Substring(reg.Root.Length + 1),
            PolicyPaths = []
        };
        try
        {
            var notes = SecretStore.MigrateReadableCopies();

            notes.Should().ContainSingle().Which.Should().StartWith("Could not move ApiKey");
            reg.GetSetting(Key).Should().Be("from-settings");
        }
        finally
        {
            SecretStore.LocationsOverride = writable;
        }
    }

    [Fact]
    public void NotesNeverContainTheValue()
    {
        using var reg = new TempRegistryKey();
        reg.SetSetting(Key, "s3cret-value");
        reg.SetString(Key, "p0licy-value");

        var notes = SecretStore.MigrateReadableCopies();

        notes.Should().NotBeEmpty();
        notes.Should().NotContain(n => n.Contains("s3cret") || n.Contains("p0licy"));
    }

    [Fact]
    public void ApiKeyResolvesFromTheStoreAfterMigration()
    {
        using var env = new EnvironmentSnapshot("CRYPT_API_KEY");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();
        reg.SetString(Key, "from-policy");
        SecretStore.MigrateReadableCopies();

        ConfigService.ResolveApiKey().Should().Be(new Resolved<string?>("from-policy", SettingSource.Policy));
    }

    [Fact]
    public void ConfigSetWritesTheStoreNotTheSettingsKey()
    {
        using var reg = new TempRegistryKey();

        ConfigService.SetValue("server.auth.api_key", "True");

        reg.GetSecret(Key).Should().Be("True", "a secret is stored exactly as given");
        reg.GetSetting(Key).Should().BeNull();
    }

    [Fact]
    public void ConfigSetRefusesASecretPolicyManages()
    {
        using var reg = new TempRegistryKey();
        reg.SetString(Key, "from-policy");
        SecretStore.MigrateReadableCopies();

        var act = () => ConfigService.SetValue("ApiKey", "mine");

        act.Should().Throw<InvalidOperationException>();
        reg.GetSecret(Key).Should().Be("from-policy");
    }

    // ------------------------------------------------------------ ACL

    [Fact]
    public void ProtectedAclAdmitsOnlySystemAndAdministrators() =>
        SecretStore.WhyUnprotected(SecretStore.ProtectedSecurity()).Should().BeNull();

    [Fact]
    public void AclThatLetsUsersReadIsRejected()
    {
        var security = SecretStore.ProtectedSecurity();
        security.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            RegistryRights.ReadKey, AccessControlType.Allow));

        SecretStore.WhyUnprotected(security).Should().Contain("S-1-5-32-545");
    }

    [Fact]
    public void InheritedAclIsRejected()
    {
        var security = SecretStore.ProtectedSecurity();
        security.SetAccessRuleProtection(isProtected: false, preserveInheritance: true);

        SecretStore.WhyUnprotected(security).Should().Contain("inherits");
    }
}

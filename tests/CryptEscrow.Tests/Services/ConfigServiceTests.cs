using CryptEscrow.Services;
using CryptEscrow.Tests.Fixtures;
using FluentAssertions;
using Xunit;

namespace CryptEscrow.Tests.Services;

/// <summary>
/// Opt-out of xUnit's default cross-class parallelism for any tests that
/// mutate process-wide state (environment variables, ConfigService static
/// overrides). All test classes that depend on <see cref="EnvironmentSnapshot"/>,
/// <see cref="TempRegistryKey"/>, or <see cref="TempConfigFile"/> should join
/// this collection.
/// </summary>
[CollectionDefinition(GlobalStateCollection.Name, DisableParallelization = true)]
public sealed class GlobalStateCollection
{
    public const string Name = "GlobalState";
}

/// <summary>
/// Covers the env-var > registry > YAML > default priority chain for every
/// GetX() helper on <see cref="ConfigService"/>, plus GetAuthConfig composition.
/// Tests never touch the real ProgramData config path or HKLM registry; see
/// <see cref="TempConfigFile"/> and <see cref="TempRegistryKey"/>.
/// </summary>
[Collection(GlobalStateCollection.Name)]
public class ConfigServiceTests
{
    // -------------------------- GetApiKey --------------------------

    [Fact]
    public void GetApiKey_EnvVarWinsOverRegistryAndYaml()
    {
        using var env = new EnvironmentSnapshot("CRYPT_API_KEY");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        reg.SetString("ApiKey", "from-registry");
        yaml.WriteYaml("server:\n  auth:\n    api_key: from-yaml\n");
        env.Set("CRYPT_API_KEY", "from-env");

        ConfigService.GetApiKey().Should().Be("from-env");
    }

    [Fact]
    public void GetApiKey_RegistryWinsOverYamlWhenEnvUnset()
    {
        using var env = new EnvironmentSnapshot("CRYPT_API_KEY");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        reg.SetString("ApiKey", "from-registry");
        yaml.WriteYaml("server:\n  auth:\n    api_key: from-yaml\n");

        ConfigService.GetApiKey().Should().Be("from-registry");
    }

    [Fact]
    public void GetApiKey_YamlUsedWhenEnvAndRegistryUnset()
    {
        using var env = new EnvironmentSnapshot("CRYPT_API_KEY");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        yaml.WriteYaml("server:\n  auth:\n    api_key: from-yaml\n");

        ConfigService.GetApiKey().Should().Be("from-yaml");
    }

    [Fact]
    public void GetApiKey_ReturnsNullWhenNothingConfigured()
    {
        using var env = new EnvironmentSnapshot("CRYPT_API_KEY");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        ConfigService.GetApiKey().Should().BeNull();
    }

    // -------------------------- GetUseMtls --------------------------

    [Fact]
    public void GetUseMtls_EnvVarWins()
    {
        using var env = new EnvironmentSnapshot("CRYPT_USE_MTLS");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        reg.SetDword("UseMtls", 0);
        env.Set("CRYPT_USE_MTLS", "true");

        ConfigService.GetUseMtls().Should().BeTrue();
    }

    [Fact]
    public void GetUseMtls_RegistryDwordWhenEnvUnset()
    {
        using var env = new EnvironmentSnapshot("CRYPT_USE_MTLS");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        reg.SetDword("UseMtls", 1);

        ConfigService.GetUseMtls().Should().BeTrue();
    }

    [Fact]
    public void GetUseMtls_DefaultsFalse()
    {
        using var env = new EnvironmentSnapshot("CRYPT_USE_MTLS");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        ConfigService.GetUseMtls().Should().BeFalse();
    }

    // ----------------------- GetClientCertPath / GetClientKeyPath ---

    [Fact]
    public void GetClientCertPath_EnvWinsOverRegistryAndYaml()
    {
        using var env = new EnvironmentSnapshot("CRYPT_CLIENT_CERT_PATH");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        reg.SetString("ClientCertPath", @"C:\reg\cert.pem");
        yaml.WriteYaml("server:\n  auth:\n    client_cert_path: C:\\yaml\\cert.pem\n");
        env.Set("CRYPT_CLIENT_CERT_PATH", @"C:\env\cert.pem");

        ConfigService.GetClientCertPath().Should().Be(@"C:\env\cert.pem");
    }

    [Fact]
    public void GetClientCertPath_RegistryWinsOverYaml()
    {
        using var env = new EnvironmentSnapshot("CRYPT_CLIENT_CERT_PATH");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        reg.SetString("ClientCertPath", @"C:\reg\cert.pem");
        yaml.WriteYaml("server:\n  auth:\n    client_cert_path: C:\\yaml\\cert.pem\n");

        ConfigService.GetClientCertPath().Should().Be(@"C:\reg\cert.pem");
    }

    [Fact]
    public void GetClientKeyPath_YamlFallback()
    {
        using var env = new EnvironmentSnapshot("CRYPT_CLIENT_KEY_PATH");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        yaml.WriteYaml("server:\n  auth:\n    client_key_path: C:\\yaml\\cert.key\n");

        ConfigService.GetClientKeyPath().Should().Be(@"C:\yaml\cert.key");
    }

    // ----------------------- GetPfxPath / GetPfxPasswordCredential --

    [Fact]
    public void GetPfxPath_EnvWinsOverRegistryAndYaml()
    {
        using var env = new EnvironmentSnapshot("CRYPT_PFX_PATH");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        reg.SetString("PfxPath", @"C:\reg\client.pfx");
        yaml.WriteYaml("server:\n  auth:\n    pfx_path: C:\\yaml\\client.pfx\n");
        env.Set("CRYPT_PFX_PATH", @"C:\env\client.pfx");

        ConfigService.GetPfxPath().Should().Be(@"C:\env\client.pfx");
    }

    [Fact]
    public void GetPfxPasswordCredential_RegistryWinsOverYaml()
    {
        using var env = new EnvironmentSnapshot("CRYPT_PFX_PASSWORD_CRED");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        reg.SetString("PfxPasswordCredential", "CryptPfxPasswordReg");
        yaml.WriteYaml("server:\n  auth:\n    pfx_password_credential: CryptPfxPasswordYaml\n");

        ConfigService.GetPfxPasswordCredential().Should().Be("CryptPfxPasswordReg");
    }

    [Fact]
    public void GetPfxPath_ReturnsNullWhenNothingConfigured()
    {
        using var env = new EnvironmentSnapshot("CRYPT_PFX_PATH");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        ConfigService.GetPfxPath().Should().BeNull();
    }

    // -------------------------- GetCertificateSubject ---------------

    [Fact]
    public void GetCertificateSubject_EnvWins()
    {
        using var env = new EnvironmentSnapshot("CRYPT_CERT_SUBJECT");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        reg.SetString("CertificateSubject", "from-reg.example.com");
        env.Set("CRYPT_CERT_SUBJECT", "from-env.example.com");

        ConfigService.GetCertificateSubject().Should().Be("from-env.example.com");
    }

    // -------------------------- GetAuthConfig composition -----------

    [Fact]
    public void GetAuthConfig_ComposesFromMixedSources()
    {
        using var env = new EnvironmentSnapshot(
            "CRYPT_API_KEY", "CRYPT_USE_MTLS", "CRYPT_PFX_PATH",
            "CRYPT_PFX_PASSWORD_CRED", "CRYPT_CLIENT_CERT_PATH",
            "CRYPT_CLIENT_KEY_PATH", "CRYPT_CERT_SUBJECT");
        using var reg = new TempRegistryKey();
        using var yaml = new TempConfigFile();

        env.Set("CRYPT_API_KEY", "env-key");
        env.Set("CRYPT_USE_MTLS", "true");
        reg.SetString("PfxPath", @"C:\reg\client.pfx");
        reg.SetString("PfxPasswordCredential", "CryptPfxPassword");
        yaml.WriteYaml(
            "server:\n" +
            "  auth:\n" +
            "    certificate_subject: yaml-subject.example.com\n" +
            "    client_cert_path: C:\\yaml\\client.pem\n" +
            "    client_key_path: C:\\yaml\\client.key\n");

        var authConfig = ConfigService.GetAuthConfig();

        authConfig.ApiKey.Should().Be("env-key");
        authConfig.UseMtls.Should().BeTrue();
        authConfig.PfxPath.Should().Be(@"C:\reg\client.pfx");
        authConfig.PfxPasswordCredential.Should().Be("CryptPfxPassword");
        authConfig.CertificateSubject.Should().Be("yaml-subject.example.com");
        authConfig.ClientCertPath.Should().Be(@"C:\yaml\client.pem");
        authConfig.ClientKeyPath.Should().Be(@"C:\yaml\client.key");
    }
}

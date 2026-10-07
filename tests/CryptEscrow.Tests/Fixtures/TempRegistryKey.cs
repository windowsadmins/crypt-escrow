using CryptEscrow.Services;
using Microsoft.Win32;

namespace CryptEscrow.Tests.Fixtures;

/// <summary>
/// Creates throwaway <c>HKCU\Software\CryptEscrowTest\&lt;guid&gt;\{Policy,Settings}</c>
/// subkeys and points <see cref="ConfigService.PolicyReaderOverride"/>,
/// <see cref="ConfigService.SettingsReaderOverride"/> and
/// <see cref="ConfigService.SettingsWriterOverride"/> at them. On dispose, restores
/// the overrides and deletes the subkeys. Lets tests exercise both registry layers
/// without admin rights, and keeps them from ever reading the machine's own HKLM values.
/// </summary>
internal sealed class TempRegistryKey : IDisposable
{
    private readonly string _root;
    private readonly string _policy;
    private readonly string _settings;
    private readonly Func<string, string?>? _previousPolicyReader;
    private readonly Func<string, string?>? _previousSettingsReader;
    private readonly Action<string, string>? _previousSettingsWriter;
    private readonly SecretStore.Locations? _previousLocations;
    private readonly Func<string, string?>? _previousEnvReader;
    private readonly Action<string>? _previousEnvClearer;
    private readonly Action<string>? _previousSettingsRemover;

    public TempRegistryKey()
    {
        _root = $@"Software\CryptEscrowTest\{Guid.NewGuid():N}";
        _policy = _root + @"\Policy";
        _settings = _root + @"\Settings";
        using (Registry.CurrentUser.CreateSubKey(_policy)) { }
        using (Registry.CurrentUser.CreateSubKey(_settings)) { }

        _previousPolicyReader = ConfigService.PolicyReaderOverride;
        _previousSettingsReader = ConfigService.SettingsReaderOverride;
        _previousSettingsWriter = ConfigService.SettingsWriterOverride;
        ConfigService.PolicyReaderOverride = name => ReadValue(_policy, name);
        ConfigService.SettingsReaderOverride = name => ReadValue(_settings, name);
        ConfigService.SettingsWriterOverride = (name, value) => Write(_settings, name, value, RegistryValueKind.String);

        // The protected store and its readable sources, all under the same HKCU subtree.
        // ACLs are not applied: a protected HKCU key would lock the test user out.
        SecretsPath = _root + @"\Secrets";
        PolicyMdmPath = _root + @"\PolicyMdm";
        _previousLocations = SecretStore.LocationsOverride;
        SecretStore.LocationsOverride = new SecretStore.Locations(
            Registry.CurrentUser, SecretsPath, [_policy, PolicyMdmPath], _settings, ApplyAcl: false);
        _previousEnvReader = SecretStore.MachineEnvironmentReader;
        _previousEnvClearer = SecretStore.MachineEnvironmentClearer;
        SecretStore.MachineEnvironmentReader = name => MachineEnvironment.TryGetValue(name, out var v) ? v : null;
        SecretStore.MachineEnvironmentClearer = name => MachineEnvironment.Remove(name);
        _previousSettingsRemover = ConfigService.SettingsRemoverOverride;
        ConfigService.SettingsRemoverOverride = name =>
        {
            using var key = Registry.CurrentUser.OpenSubKey(_settings, writable: true);
            key?.DeleteValue(name, throwOnMissingValue: false);
        };
    }

    public string Root => _root;
    public string SecretsPath { get; }
    public string PolicyMdmPath { get; }

    /// <summary>Stand-in for machine-level environment variables.</summary>
    public Dictionary<string, string> MachineEnvironment { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Reads back a policy value as stored, including an empty one.</summary>
    public object? GetPolicy(string name)
    {
        using var key = Registry.CurrentUser.OpenSubKey(_policy);
        return key?.GetValue(name);
    }

    /// <summary>Reads back a protected-store value as stored.</summary>
    public object? GetSecret(string name)
    {
        using var key = Registry.CurrentUser.OpenSubKey(SecretsPath);
        return key?.GetValue(name);
    }

    /// <summary>Sets a policy value.</summary>
    public void SetString(string name, string value) => Write(_policy, name, value, RegistryValueKind.String);

    /// <summary>Sets a policy value.</summary>
    public void SetDword(string name, int value) => Write(_policy, name, value, RegistryValueKind.DWord);

    /// <summary>Sets a policy value.</summary>
    public void SetQword(string name, long value) => Write(_policy, name, value, RegistryValueKind.QWord);

    /// <summary>Sets a machine settings value.</summary>
    public void SetSetting(string name, string value) => Write(_settings, name, value, RegistryValueKind.String);

    /// <summary>Sets a machine settings value.</summary>
    public void SetSettingDword(string name, int value) => Write(_settings, name, value, RegistryValueKind.DWord);

    /// <summary>Reads back a machine settings value as stored.</summary>
    public object? GetSetting(string name)
    {
        using var key = Registry.CurrentUser.OpenSubKey(_settings);
        return key?.GetValue(name);
    }

    /// <summary>
    /// Opens the policy subkey for direct <see cref="RegistryKey.GetValue(string)"/>
    /// access. Caller must dispose. Used by tests that want to exercise the
    /// production <see cref="ConfigService.ConvertToConfigString"/> path against
    /// a real <see cref="RegistryKey"/> (without going through the reader seam).
    /// </summary>
    public RegistryKey OpenKey() =>
        Registry.CurrentUser.OpenSubKey(_policy)
        ?? throw new InvalidOperationException($"Temp registry key disappeared: {_policy}");

    private static void Write(string path, string name, object value, RegistryValueKind kind)
    {
        using var key = Registry.CurrentUser.OpenSubKey(path, writable: true)
            ?? throw new InvalidOperationException($"Temp registry key disappeared: {path}");
        key.SetValue(name, value, kind);
    }

    private static string? ReadValue(string path, string name)
    {
        // Delegate to the production helper so test behavior stays in sync with
        // what the HKLM reads would actually do.
        using var key = Registry.CurrentUser.OpenSubKey(path);
        return ConfigService.ConvertToConfigString(key?.GetValue(name));
    }

    public void Dispose()
    {
        ConfigService.PolicyReaderOverride = _previousPolicyReader;
        ConfigService.SettingsReaderOverride = _previousSettingsReader;
        ConfigService.SettingsWriterOverride = _previousSettingsWriter;
        SecretStore.LocationsOverride = _previousLocations;
        SecretStore.MachineEnvironmentReader = _previousEnvReader;
        SecretStore.MachineEnvironmentClearer = _previousEnvClearer;
        ConfigService.SettingsRemoverOverride = _previousSettingsRemover;
        try
        {
            Registry.CurrentUser.DeleteSubKeyTree(_root, throwOnMissingSubKey: false);
        }
        catch
        {
            // Best-effort cleanup; don't fail tests during teardown.
        }
    }
}

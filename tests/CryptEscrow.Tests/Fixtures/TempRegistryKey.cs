using CryptEscrow.Services;
using Microsoft.Win32;

namespace CryptEscrow.Tests.Fixtures;

/// <summary>
/// Creates a throwaway <c>HKCU\Software\CryptEscrowTest\&lt;guid&gt;</c> subkey and
/// installs a <see cref="ConfigService.RegistryReaderOverride"/> that reads from
/// it. On dispose, restores the override and deletes the subkey.
/// Lets tests exercise the registry code path without admin rights.
/// </summary>
internal sealed class TempRegistryKey : IDisposable
{
    private readonly string _path;
    private readonly Func<string, string?>? _previousReader;

    public TempRegistryKey()
    {
        _path = $@"Software\CryptEscrowTest\{Guid.NewGuid():N}";
        using (Registry.CurrentUser.CreateSubKey(_path)) { }

        _previousReader = ConfigService.RegistryReaderOverride;
        ConfigService.RegistryReaderOverride = ReadValue;
    }

    public void SetString(string name, string value)
    {
        using var key = Registry.CurrentUser.OpenSubKey(_path, writable: true)
            ?? throw new InvalidOperationException($"Temp registry key disappeared: {_path}");
        key.SetValue(name, value, RegistryValueKind.String);
    }

    public void SetDword(string name, int value)
    {
        using var key = Registry.CurrentUser.OpenSubKey(_path, writable: true)
            ?? throw new InvalidOperationException($"Temp registry key disappeared: {_path}");
        key.SetValue(name, value, RegistryValueKind.DWord);
    }

    public void SetQword(string name, long value)
    {
        using var key = Registry.CurrentUser.OpenSubKey(_path, writable: true)
            ?? throw new InvalidOperationException($"Temp registry key disappeared: {_path}");
        key.SetValue(name, value, RegistryValueKind.QWord);
    }

    /// <summary>
    /// Opens the underlying temp subkey for direct <see cref="RegistryKey.GetValue(string)"/>
    /// access. Caller must dispose. Used by tests that want to exercise the
    /// production <see cref="ConfigService.ConvertToConfigString"/> path against
    /// a real <see cref="RegistryKey"/> (without going through the reader seam).
    /// </summary>
    public RegistryKey OpenKey() =>
        Registry.CurrentUser.OpenSubKey(_path)
        ?? throw new InvalidOperationException($"Temp registry key disappeared: {_path}");

    private string? ReadValue(string name)
    {
        // Delegate to the production helper so test behavior stays in sync with
        // what GetRegistryValue would actually do against HKLM.
        using var key = Registry.CurrentUser.OpenSubKey(_path);
        return ConfigService.ConvertToConfigString(key?.GetValue(name));
    }

    public void Dispose()
    {
        ConfigService.RegistryReaderOverride = _previousReader;
        try
        {
            Registry.CurrentUser.DeleteSubKeyTree(_path, throwOnMissingSubKey: false);
        }
        catch
        {
            // Best-effort cleanup; don't fail tests during teardown.
        }
    }
}

using CryptEscrow.Services;

namespace CryptEscrow.Tests.Fixtures;

/// <summary>
/// Creates a throwaway config.yaml in a unique temp directory and points
/// <see cref="ConfigService.ConfigPathOverride"/> at it. On dispose, restores
/// the override and deletes the directory.
/// </summary>
internal sealed class TempConfigFile : IDisposable
{
    private readonly string _dir;
    private readonly string? _previousOverride;

    public TempConfigFile()
    {
        _dir = Path.Combine(Path.GetTempPath(), "crypt-escrow-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        FilePath = Path.Combine(_dir, "config.yaml");
        _previousOverride = ConfigService.ConfigPathOverride;
        ConfigService.ConfigPathOverride = FilePath;
    }

    public string FilePath { get; }

    /// <summary>
    /// Writes raw YAML to the config file, overwriting any previous content.
    /// </summary>
    public void WriteYaml(string yaml)
    {
        File.WriteAllText(FilePath, yaml);
    }

    public void Dispose()
    {
        ConfigService.ConfigPathOverride = _previousOverride;
        try
        {
            if (Directory.Exists(_dir))
                Directory.Delete(_dir, recursive: true);
        }
        catch
        {
            // Best-effort cleanup.
        }
    }
}

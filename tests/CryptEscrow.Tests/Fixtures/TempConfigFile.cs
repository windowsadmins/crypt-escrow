using CryptEscrow.Services;

namespace CryptEscrow.Tests.Fixtures;

/// <summary>
/// Creates a throwaway config.yaml in a unique temp directory and points
/// <see cref="ConfigService.ConfigPathOverride"/> at it. On dispose, restores
/// the override and deletes the directory.
/// The file counts as trusted unless <see cref="MarkUntrusted"/> is called: a temp
/// directory is owned by the test user, so the real ACL check would always reject it.
/// <c>TrustedFileTests</c> covers that check on its own.
/// </summary>
internal sealed class TempConfigFile : IDisposable
{
    private readonly string _dir;
    private readonly string? _previousOverride;
    private readonly Func<string, string?>? _previousTrust;
    private string? _untrustedReason;

    public TempConfigFile()
    {
        _dir = Path.Combine(Path.GetTempPath(), "crypt-escrow-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        FilePath = Path.Combine(_dir, "config.yaml");
        _previousOverride = ConfigService.ConfigPathOverride;
        ConfigService.ConfigPathOverride = FilePath;
        _previousTrust = ConfigService.FileTrustOverride;
        ConfigService.FileTrustOverride = _ => _untrustedReason;
        ConfigService.ClearIgnoredFileNotes();
    }

    /// <summary>Makes the ACL check reject the file with <paramref name="reason"/>.</summary>
    public void MarkUntrusted(string reason) => _untrustedReason = reason;

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
        ConfigService.FileTrustOverride = _previousTrust;
        ConfigService.ClearIgnoredFileNotes();
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

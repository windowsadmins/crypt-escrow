namespace CryptEscrow;

/// <summary>
/// Where the CLI writes its log. The app reads the same layout to stream a run and to
/// list past sessions, so both sides share this one definition.
/// </summary>
public static class LogLayout
{
    public const string DayFormat = "yyyy-MM-dd";
    public const string DefaultFileName = "crypt-escrow.log";
    public const string EventsFileName = "events.jsonl";

    /// <summary>%ProgramData%\ManagedEncryption\logs unless the config says otherwise.</summary>
    public static string ResolveLogDirectory(string? configured)
    {
        if (!string.IsNullOrWhiteSpace(configured))
            return Path.GetDirectoryName(configured!) ?? configured!;

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "ManagedEncryption", "logs");
    }

    /// <summary>The log for a run starting at <paramref name="timestamp"/>: one directory per day.</summary>
    public static string ResolveLogPath(string? configured, DateTime timestamp)
    {
        if (!string.IsNullOrWhiteSpace(configured))
        {
            var directory = Path.GetDirectoryName(configured!);
            var name = Path.GetFileName(configured!);
            return string.IsNullOrEmpty(directory)
                ? configured!
                : Path.Combine(directory, timestamp.ToString(DayFormat), name);
        }

        return Path.Combine(ResolveLogDirectory(null), timestamp.ToString(DayFormat), DefaultFileName);
    }
}

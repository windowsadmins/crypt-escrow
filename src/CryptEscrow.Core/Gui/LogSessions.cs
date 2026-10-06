using System.Globalization;

namespace CryptEscrow.Gui;

/// <summary>One log file the Logs tab can show.</summary>
public sealed record LogSession(string Name, string Path, DateTime? Date, long SizeBytes)
{
    public string DisplayDate => Date is { } d ? d.ToString("dddd d MMMM yyyy", CultureInfo.CurrentCulture) : Name;

    public string DisplayTime => Date is { } d ? d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : "";

    public string DisplaySize => SizeBytes switch
    {
        < 1024 => $"{SizeBytes} B",
        < 1024 * 1024 => $"{SizeBytes / 1024.0:0.#} KB",
        _ => $"{SizeBytes / (1024.0 * 1024):0.#} MB",
    };
}

public enum LogLineLevel { Default, Debug, Info, Warning, Error }

/// <summary>Reads the CLI's log layout: one directory per day, newest first.</summary>
public static class LogSessions
{
    /// <summary>
    /// Every day directory's log, plus flat logs at the root from the previous layout,
    /// newest first. The structured event stream is left out.
    /// </summary>
    public static IReadOnlyList<LogSession> List(string logDirectory)
    {
        if (!Directory.Exists(logDirectory))
            return [];

        var sessions = new List<LogSession>();

        foreach (var day in SafeDirectories(logDirectory))
        {
            if (!DateTime.TryParseExact(System.IO.Path.GetFileName(day), LogLayout.DayFormat,
                    CultureInfo.InvariantCulture, DateTimeStyles.None, out var date))
                continue;

            foreach (var file in SafeFiles(day, "*.log"))
                sessions.Add(new LogSession(System.IO.Path.GetFileName(day), file, date, FileSize(file)));
        }

        foreach (var file in SafeFiles(logDirectory, "*.log"))
            sessions.Add(new LogSession(System.IO.Path.GetFileName(file), file, LastWrite(file), FileSize(file)));

        return sessions
            .OrderByDescending(s => s.Date ?? DateTime.MinValue)
            .ThenBy(s => s.Name, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>
    /// The level of a log line. The file log writes "[yyyy-MM-dd HH:mm:ss] LEVEL message"
    /// and the console writes "[HH:mm:ss] [WRN] message"; both are recognised.
    /// </summary>
    public static LogLineLevel Classify(string line)
    {
        var close = line.IndexOf("] ", StringComparison.Ordinal);
        if (close < 0)
            return LogLineLevel.Default;

        var rest = line.AsSpan(close + 2).TrimStart();
        if (Starts(rest, "ERROR") || Starts(rest, "[ERR]") || Starts(rest, "[FTL]")) return LogLineLevel.Error;
        if (Starts(rest, "WARN") || Starts(rest, "[WRN]")) return LogLineLevel.Warning;
        if (Starts(rest, "DEBUG") || Starts(rest, "[DBG]") || Starts(rest, "[VRB]")) return LogLineLevel.Debug;
        if (Starts(rest, "INFO") || Starts(rest, "[INF]")) return LogLineLevel.Info;
        return LogLineLevel.Default;
    }

    private static bool Starts(ReadOnlySpan<char> rest, string token) =>
        rest.StartsWith(token, StringComparison.Ordinal) &&
        (rest.Length == token.Length || rest[token.Length] == ' ');

    /// <summary>Reads a log that may still be open for writing.</summary>
    public static string ReadShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static IEnumerable<string> SafeDirectories(string path)
    {
        try { return Directory.GetDirectories(path); } catch { return []; }
    }

    private static IEnumerable<string> SafeFiles(string path, string pattern)
    {
        try { return Directory.GetFiles(path, pattern); } catch { return []; }
    }

    private static long FileSize(string path)
    {
        try { return new FileInfo(path).Length; } catch { return 0; }
    }

    private static DateTime? LastWrite(string path)
    {
        try { return File.GetLastWriteTime(path); } catch { return null; }
    }
}

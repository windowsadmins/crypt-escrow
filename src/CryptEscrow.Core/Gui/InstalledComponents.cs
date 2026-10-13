using System.Globalization;
using System.Xml;
using System.Xml.Linq;

namespace CryptEscrow.Gui;

public enum ComponentKind { Service, ScheduledTask }

/// <summary>A Windows service or scheduled task this tool's installer creates.</summary>
public sealed record InstalledComponent(string Name, ComponentKind Kind, string FriendlyName, string Description)
{
    public string KindText => Kind == ComponentKind.Service ? "Service" : "Scheduled task";
}

/// <summary>One row of the Services card: what is installed and how it is doing.</summary>
public sealed record ComponentStatus(InstalledComponent Component, string State, string LastResult, string Schedule)
{
    public string FriendlyName => Component.FriendlyName;
    public string Caption => $"{Component.Name} · {Component.KindText}";
    public string Description => Component.Description;
}

/// <summary>
/// The tool's install footprint and the plain-words formatting the Services card shows.
/// The installer registers one scheduled task (checkin register-task --frequency hourly)
/// and no Windows services.
/// </summary>
public static class InstalledComponents
{
    public const string EscrowTaskName = "CryptEscrow - BitLocker Key Sync";

    public static IReadOnlyList<InstalledComponent> All { get; } =
    [
        new(EscrowTaskName, ComponentKind.ScheduledTask, "BitLocker key sync",
            "Escrows this device's BitLocker recovery key to the Crypt server, and rotates it when the server asks."),
    ];

    // Task Scheduler result codes that are not failures.
    internal const int TaskHasNotRun = 0x41303;
    internal const int TaskIsRunning = 0x41301;

    public static ComponentStatus NotInstalled(InstalledComponent component) =>
        new(component, "Not installed", "—", "—");

    public static ComponentStatus Unknown(InstalledComponent component) =>
        new(component, "Unknown", "Unknown", "Unknown");

    /// <summary>TASK_STATE as the card shows it.</summary>
    public static string TaskStateWords(int state) => state switch
    {
        1 => "Disabled",
        2 or 3 => "Ready",
        4 => "Running",
        _ => "Unknown"
    };

    /// <summary>A task's last run and its result; "Never run" when it has not run.</summary>
    public static string TaskResultWords(int result, DateTime? lastRun, IFormatProvider? culture = null)
    {
        if (result == TaskHasNotRun || lastRun is null || lastRun.Value.Year < 2000)
            return "Never run";

        var words = result switch
        {
            0 => "Succeeded",
            TaskIsRunning => "Running",
            _ => $"Failed (0x{result:X})"
        };
        return $"{words} · {lastRun.Value.ToString("g", culture ?? CultureInfo.CurrentCulture)}";
    }

    private static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    /// <summary>A task definition's triggers in plain words, joined with "; ".</summary>
    public static string TriggersToWords(string taskXml)
    {
        XElement? triggers;
        try
        {
            triggers = XDocument.Parse(taskXml).Root?.Element(Ns + "Triggers");
        }
        catch (XmlException)
        {
            return "Unknown";
        }

        var words = triggers?.Elements()
            .Where(t => !string.Equals((string?)t.Element(Ns + "Enabled"), "false", StringComparison.OrdinalIgnoreCase))
            .Select(TriggerWords)
            .ToList() ?? [];
        return words.Count == 0 ? "No trigger" : string.Join("; ", words);
    }

    private static string TriggerWords(XElement trigger)
    {
        var start = ParseStart((string?)trigger.Element(Ns + "StartBoundary"));
        var at = start is { } s ? $" at {Time(s)}" : "";

        var words = trigger.Name.LocalName switch
        {
            "BootTrigger" => "At startup",
            "LogonTrigger" => trigger.Element(Ns + "UserId") is { } user ? $"At logon of {user.Value}" : "At logon of any user",
            "IdleTrigger" => "When the device is idle",
            "RegistrationTrigger" => "When the task is registered",
            "EventTrigger" => "When an event is logged",
            "SessionStateChangeTrigger" => "When a session changes",
            "TimeTrigger" => start is { } once ? $"Once at {once.ToString("g", CultureInfo.InvariantCulture)}" : "Once",
            "CalendarTrigger" => CalendarWords(trigger, at),
            var other => other
        };

        // A repeating trigger (schtasks /SC HOURLY is a time trigger that repeats) reads by its interval.
        var interval = (string?)trigger.Element(Ns + "Repetition")?.Element(Ns + "Interval");
        if (Every(interval) is not { } every)
            return words;
        return trigger.Name.LocalName == "TimeTrigger" ? every : $"{words}, then {every.ToLowerInvariant()}";
    }

    private static string CalendarWords(XElement trigger, string at)
    {
        if (trigger.Element(Ns + "ScheduleByDay") is { } byDay)
        {
            var days = (int?)byDay.Element(Ns + "DaysInterval") ?? 1;
            return days == 1 ? $"Daily{at}" : $"Every {days} days{at}";
        }
        if (trigger.Element(Ns + "ScheduleByWeek") is { } byWeek)
        {
            var names = byWeek.Element(Ns + "DaysOfWeek")?.Elements().Select(d => d.Name.LocalName).ToList() ?? [];
            var weeks = (int?)byWeek.Element(Ns + "WeeksInterval") ?? 1;
            var on = names.Count > 0 ? $" on {string.Join(", ", names)}" : "";
            return weeks == 1 ? $"Weekly{on}{at}" : $"Every {weeks} weeks{on}{at}";
        }
        if (trigger.Element(Ns + "ScheduleByMonth") is not null || trigger.Element(Ns + "ScheduleByMonthDayOfWeek") is not null)
            return $"Monthly{at}";
        return $"On a schedule{at}";
    }

    /// <summary>An ISO 8601 repetition interval ("PT4H") as "Every 4 hours".</summary>
    internal static string? Every(string? interval)
    {
        if (string.IsNullOrWhiteSpace(interval))
            return null;
        TimeSpan span;
        try
        {
            span = XmlConvert.ToTimeSpan(interval);
        }
        catch (FormatException)
        {
            return null;
        }
        if (span <= TimeSpan.Zero)
            return null;

        static string Unit(int n, string unit) => n == 1 ? $"Every {unit}" : $"Every {n} {unit}s";
        if (span.TotalDays >= 1 && span.TotalDays == Math.Floor(span.TotalDays))
            return Unit((int)span.TotalDays, "day");
        if (span.TotalHours >= 1 && span.TotalHours == Math.Floor(span.TotalHours))
            return Unit((int)span.TotalHours, "hour");
        return Unit((int)Math.Round(span.TotalMinutes), "minute");
    }

    private static DateTime? ParseStart(string? value) =>
        DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var start) ? start : null;

    private static string Time(DateTime time) => time.ToString("h:mm tt", CultureInfo.InvariantCulture);
}

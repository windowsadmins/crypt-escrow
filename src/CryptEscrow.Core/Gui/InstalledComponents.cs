using System.Globalization;
using System.Xml;
using System.Xml.Linq;

namespace CryptEscrow.Gui;

public enum ComponentKind { Service, ScheduledTask }

/// <summary>A Windows service or scheduled task this tool's installer creates.</summary>
public sealed record InstalledComponent(string Name, ComponentKind Kind, string FriendlyName, string Description)
{
    public string KindText => Kind == ComponentKind.Service ? "Service" : "Scheduled task";

    /// <summary>The name as Windows shows it: a task with its folder path.</summary>
    public string DisplayName => Kind == ComponentKind.ScheduledTask && !Name.StartsWith('\\') ? "\\" + Name : Name;
}

/// <summary>One label and value in an expanded Services row.</summary>
public sealed record ComponentDetail(string Label, string Value);

/// <summary>
/// One Services row: what is installed, its state, the one-line summary its collapsed
/// header shows, and the details it expands to.
/// </summary>
public sealed record ComponentStatus(InstalledComponent Component, string State, string Summary, IReadOnlyList<ComponentDetail> Details)
{
    public string FriendlyName => Component.FriendlyName;
    public string Description => Component.Description;

    /// <summary>The theme brush for the state dot.</summary>
    public string StateBrushKey => InstalledComponents.StateBrushKey(State);
}

/// <summary>What the Task Scheduler reports for one task.</summary>
public sealed record TaskSnapshot(int State, bool Enabled, DateTime? LastRun, int LastResult, DateTime? NextRun, string Xml);

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

    public const string UnknownText = "Unknown";

    public static ComponentStatus Checking(InstalledComponent component) =>
        new(component, "Checking…", component.KindText, [NameRow(component)]);

    /// <summary>Absent from the device: only its name and status are shown.</summary>
    public static ComponentStatus NotInstalled(InstalledComponent component) =>
        new(component, "Not installed", component.KindText, [NameRow(component), new("Status", "Not installed")]);

    /// <summary>
    /// Present but unreadable without elevation: every field the card would show exists,
    /// so each reads Unknown.
    /// </summary>
    public static ComponentStatus Unknown(InstalledComponent component) =>
        new(component, UnknownText, Summary(component.KindText, UnknownText),
            [NameRow(component), .. (component.Kind == ComponentKind.ScheduledTask ? TaskLabels : ["Status"])
                .Select(l => new ComponentDetail(l, UnknownText))]);

    private static ComponentDetail NameRow(InstalledComponent component) => new("Name", component.DisplayName);

    /// <summary>The collapsed header's second line: its parts joined with " · ".</summary>
    public static string Summary(params string[] parts) => string.Join(" · ", parts.Where(p => !string.IsNullOrEmpty(p)));

    /// <summary>A task's last result as the summary shows it: the code, or "Never run".</summary>
    public static string LastResultSummary(int result, DateTime? lastRun)
    {
        if (result == TaskHasNotRun || !HasRun(lastRun))
            return "Never run";
        return result == 0 ? "Last result 0" : $"Last result 0x{result:X}";
    }

    private static readonly string[] TaskLabels =
        ["Start type", "Status", "Account", "Path and arguments", "Triggers", "Last run", "Last result", "Next run"];

    /// <summary>The expanded rows for a task, in the card's fixed order; a row with no value is left out.</summary>
    public static ComponentStatus FromTask(InstalledComponent component, TaskSnapshot task, IFormatProvider? culture = null)
    {
        var state = task.Enabled ? TaskStateWords(task.State) : "Disabled";
        var rows = new List<ComponentDetail>
        {
            NameRow(component),
            new("Start type", task.Enabled ? "Enabled" : "Disabled"),
            new("Status", state)
        };
        if (PrincipalToAccount(task.Xml) is { } account)
            rows.Add(new("Account", account));
        if (ActionsToCommands(task.Xml) is { } commands)
            rows.Add(new("Path and arguments", commands));
        var triggers = TriggersToWords(task.Xml, culture);
        rows.Add(new("Triggers", triggers));
        rows.Add(new("Last run", RunTime(task.LastRun, "Never", culture)));
        rows.Add(new("Last result", TaskResultWords(task.LastResult, task.LastRun)));
        rows.Add(new("Next run", RunTime(task.NextRun, "Not scheduled", culture)));
        var summary = Summary(component.KindText, triggers, LastResultSummary(task.LastResult, task.LastRun));
        return new ComponentStatus(component, state, summary, rows);
    }

    /// <summary>The state dot's colour: theme brushes only, nothing orange.</summary>
    public static string StateBrushKey(string state) => state switch
    {
        "Running" => "SystemFillColorSuccessBrush",
        "Ready" => "SystemFillColorAttentionBrush",
        _ => "SystemFillColorNeutralBrush"
    };

    /// <summary>TASK_STATE as the card shows it.</summary>
    public static string TaskStateWords(int state) => state switch
    {
        1 => "Disabled",
        2 or 3 => "Ready",
        4 => "Running",
        _ => UnknownText
    };

    /// <summary>A task's last result in words; "Never run" when it has not run.</summary>
    public static string TaskResultWords(int result, DateTime? lastRun)
    {
        if (result == TaskHasNotRun || !HasRun(lastRun))
            return "Never run";
        return result switch
        {
            0 => "Succeeded",
            TaskIsRunning => "Running",
            _ => $"Failed (0x{result:X})"
        };
    }

    /// <summary>A local date and time, or <paramref name="none"/> for the scheduler's empty date.</summary>
    public static string RunTime(DateTime? time, string none, IFormatProvider? culture = null) =>
        HasRun(time) ? time!.Value.ToString("g", culture ?? CultureInfo.CurrentCulture) : none;

    // The Task Scheduler reports "no time" as 30 December 1899.
    private static bool HasRun(DateTime? time) => time is { Year: >= 2000 };

    /// <summary>The account a task runs as, from its principal: a well-known SID by name.</summary>
    public static string? PrincipalToAccount(string taskXml)
    {
        var principal = Parse(taskXml)?.Root?.Element(Ns + "Principals")?.Element(Ns + "Principal");
        var account = (string?)principal?.Element(Ns + "UserId") ?? (string?)principal?.Element(Ns + "GroupId");
        if (string.IsNullOrWhiteSpace(account))
            return null;
        return account.Trim().ToUpperInvariant() switch
        {
            "S-1-5-18" => "SYSTEM",
            "S-1-5-19" => "LOCAL SERVICE",
            "S-1-5-20" => "NETWORK SERVICE",
            "S-1-5-32-544" => "Administrators",
            "S-1-5-32-545" => "Users",
            _ => account.Trim()
        };
    }

    /// <summary>Each Exec action's command and arguments, one per line.</summary>
    public static string? ActionsToCommands(string taskXml)
    {
        var lines = Parse(taskXml)?.Root?.Element(Ns + "Actions")?.Elements(Ns + "Exec")
            .Select(exec =>
            {
                var command = ((string?)exec.Element(Ns + "Command"))?.Trim() ?? "";
                if (command.Contains(' ') && !command.StartsWith('"'))
                    command = $"\"{command}\"";
                var arguments = ((string?)exec.Element(Ns + "Arguments"))?.Trim();
                return string.IsNullOrEmpty(arguments) ? command : $"{command} {arguments}";
            })
            .Where(l => l.Length > 0)
            .ToList();
        return lines is { Count: > 0 } ? string.Join("\n", lines) : null;
    }

    private static XDocument? Parse(string xml)
    {
        try
        {
            return XDocument.Parse(xml);
        }
        catch (XmlException)
        {
            return null;
        }
    }

    private static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    /// <summary>
    /// A task definition's triggers in plain words, joined with "; ". Times of day use the
    /// culture's short time pattern ("t"), the current culture unless one is given.
    /// </summary>
    public static string TriggersToWords(string taskXml, IFormatProvider? culture = null)
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
            .Select(t => TriggerWords(t, culture ?? CultureInfo.CurrentCulture))
            .ToList() ?? [];
        return words.Count == 0 ? "No trigger" : string.Join("; ", words);
    }

    private static string TriggerWords(XElement trigger, IFormatProvider culture)
    {
        var start = ParseStart((string?)trigger.Element(Ns + "StartBoundary"));
        var at = start is { } s ? $" at {s.ToString("t", culture)}" : "";

        var words = trigger.Name.LocalName switch
        {
            "BootTrigger" => "At startup",
            "LogonTrigger" => trigger.Element(Ns + "UserId") is { } user ? $"At logon of {user.Value}" : "At logon of any user",
            "IdleTrigger" => "When the device is idle",
            "RegistrationTrigger" => "When the task is registered",
            "EventTrigger" => "When an event is logged",
            "SessionStateChangeTrigger" => "When a session changes",
            "TimeTrigger" => start is { } once ? $"Once at {once.ToString("g", culture)}" : "Once",
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
}

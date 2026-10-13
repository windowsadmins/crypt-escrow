using System.Globalization;
using CryptEscrow.Gui;
using FluentAssertions;
using Xunit;

namespace CryptEscrow.Tests.Gui;

public class InstalledComponentsTests
{
    private const string Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    private static string Task(string triggers, string principals = "", string actions = "") => $"""
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="{Ns}">
          <Triggers>{triggers}</Triggers>
          <Principals>{principals}</Principals>
          <Actions Context="Author">{actions}</Actions>
        </Task>
        """.Trim();

    // What `checkin register-task --frequency hourly` registers, as schtasks writes it.
    private static readonly string EscrowTaskXml = Task(
        """
        <TimeTrigger>
          <Repetition><Interval>PT1H</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
          <StartBoundary>2026-10-12T14:37:00</StartBoundary>
          <Enabled>true</Enabled>
        </TimeTrigger>
        """,
        """<Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>""",
        """<Exec><Command>C:\Program Files\Crypt\checkin.exe</Command><Arguments>escrow</Arguments></Exec>""");

    [Fact]
    public void FootprintIsTheHourlyEscrowTaskAndNoServices()
    {
        InstalledComponents.All.Should().ContainSingle()
            .Which.Should().Match<InstalledComponent>(c =>
                c.Name == "CryptEscrow - BitLocker Key Sync" && c.Kind == ComponentKind.ScheduledTask);
        InstalledComponents.All.Should().NotContain(c => c.Kind == ComponentKind.Service);
    }

    [Fact]
    public void HourlyTaskFromSchtasksReadsAsEveryHour() =>
        InstalledComponents.TriggersToWords(EscrowTaskXml).Should().Be("Every hour");

    [Theory]
    [InlineData("<BootTrigger><Enabled>true</Enabled></BootTrigger>", "At startup")]
    [InlineData("<LogonTrigger><Enabled>true</Enabled></LogonTrigger>", "At logon of any user")]
    [InlineData("<CalendarTrigger><StartBoundary>2026-01-01T03:00:00</StartBoundary><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>", "Daily at 3:00 AM")]
    [InlineData("<CalendarTrigger><StartBoundary>2026-01-01T08:00:00</StartBoundary><ScheduleByDay><DaysInterval>2</DaysInterval></ScheduleByDay></CalendarTrigger>", "Every 2 days at 8:00 AM")]
    [InlineData("<CalendarTrigger><StartBoundary>2026-01-05T08:00:00</StartBoundary><ScheduleByWeek><DaysOfWeek><Monday /></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek></CalendarTrigger>", "Weekly on Monday at 8:00 AM")]
    [InlineData("<TimeTrigger><StartBoundary>2026-01-01T00:00:00</StartBoundary><Repetition><Interval>PT4H</Interval></Repetition></TimeTrigger>", "Every 4 hours")]
    [InlineData("<CalendarTrigger><StartBoundary>2026-01-01T06:00:00</StartBoundary><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay><Repetition><Interval>PT30M</Interval></Repetition></CalendarTrigger>", "Daily at 6:00 AM, then every 30 minutes")]
    public void TriggersReadInPlainWords(string trigger, string expected) =>
        InstalledComponents.TriggersToWords(Task(trigger)).Should().Be(expected);

    [Fact]
    public void SeveralTriggersAreJoinedAndDisabledOnesSkipped() =>
        InstalledComponents.TriggersToWords(Task("""
            <BootTrigger />
            <LogonTrigger><Enabled>false</Enabled></LogonTrigger>
            <LogonTrigger><UserId>EXAMPLE\kiosk</UserId></LogonTrigger>
            """)).Should().Be(@"At startup; At logon of EXAMPLE\kiosk");

    [Theory]
    [InlineData("<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers /></Task>", "No trigger")]
    [InlineData("not xml", "Unknown")]
    public void MissingOrUnreadableTriggers(string xml, string expected) =>
        InstalledComponents.TriggersToWords(xml).Should().Be(expected);

    [Theory]
    [InlineData("<Principal><UserId>S-1-5-18</UserId></Principal>", "SYSTEM")]
    [InlineData("<Principal><UserId>S-1-5-20</UserId></Principal>", "NETWORK SERVICE")]
    [InlineData("<Principal><GroupId>S-1-5-32-545</GroupId></Principal>", "Users")]
    [InlineData(@"<Principal><UserId>EXAMPLE\svc-escrow</UserId></Principal>", @"EXAMPLE\svc-escrow")]
    [InlineData("", null)]
    public void PrincipalReadsAsAnAccount(string principal, string? expected) =>
        InstalledComponents.PrincipalToAccount(Task("", principal)).Should().Be(expected);

    [Fact]
    public void ActionsReadAsQuotedCommandAndArgumentsOnePerLine()
    {
        InstalledComponents.ActionsToCommands(EscrowTaskXml)
            .Should().Be("\"C:\\Program Files\\Crypt\\checkin.exe\" escrow");

        InstalledComponents.ActionsToCommands(Task("", "", """
            <Exec><Command>cmd.exe</Command></Exec>
            <Exec><Command>"C:\Tools\a b.exe"</Command><Arguments>--x</Arguments></Exec>
            """)).Should().Be("cmd.exe\n\"C:\\Tools\\a b.exe\" --x");

        InstalledComponents.ActionsToCommands(Task("")).Should().BeNull();
    }

    [Theory]
    [InlineData(1, "Disabled")]
    [InlineData(3, "Ready")]
    [InlineData(2, "Ready")]
    [InlineData(4, "Running")]
    [InlineData(0, "Unknown")]
    public void TaskStateWords(int state, string expected) =>
        InstalledComponents.TaskStateWords(state).Should().Be(expected);

    [Fact]
    public void TaskResultsReadInWords()
    {
        var lastRun = new DateTime(2026, 10, 12, 14, 0, 0);

        InstalledComponents.TaskResultWords(0, lastRun).Should().Be("Succeeded");
        InstalledComponents.TaskResultWords(1, lastRun).Should().Be("Failed (0x1)");
        InstalledComponents.TaskResultWords(unchecked((int)0x8007010B), lastRun).Should().Be("Failed (0x8007010B)");
        InstalledComponents.TaskResultWords(0x41303, lastRun).Should().Be("Never run");
        InstalledComponents.TaskResultWords(0, new DateTime(1899, 12, 30)).Should().Be("Never run");
        InstalledComponents.TaskResultWords(0, null).Should().Be("Never run");
    }

    [Fact]
    public void RunTimesReadAsLocalTimeOrTheirEmptyWord()
    {
        var culture = CultureInfo.InvariantCulture;
        InstalledComponents.RunTime(new DateTime(2026, 10, 12, 14, 0, 0), "Never", culture).Should().Be("10/12/2026 14:00");
        InstalledComponents.RunTime(new DateTime(1899, 12, 30), "Never", culture).Should().Be("Never");
        InstalledComponents.RunTime(null, "Not scheduled", culture).Should().Be("Not scheduled");
    }

    [Theory]
    [InlineData("PT1H", "Every hour")]
    [InlineData("PT4H", "Every 4 hours")]
    [InlineData("PT15M", "Every 15 minutes")]
    [InlineData("P1D", "Every day")]
    [InlineData("", null)]
    [InlineData("garbage", null)]
    public void RepetitionIntervals(string interval, string? expected) =>
        InstalledComponents.Every(interval).Should().Be(expected);

    [Theory]
    [InlineData("Running", "SystemFillColorSuccessBrush")]
    [InlineData("Ready", "SystemFillColorAttentionBrush")]
    [InlineData("Disabled", "SystemFillColorNeutralBrush")]
    [InlineData("Not installed", "SystemFillColorNeutralBrush")]
    [InlineData("Unknown", "SystemFillColorNeutralBrush")]
    public void StateDotUsesThemeBrushesOnly(string state, string brush) =>
        InstalledComponents.StateBrushKey(state).Should().Be(brush);

    [Fact]
    public void ReadableTaskShowsSummaryAndTheDetailRowsInOrder()
    {
        var culture = CultureInfo.InvariantCulture;
        var status = InstalledComponents.FromTask(InstalledComponents.All[0], new TaskSnapshot(
            State: 3, Enabled: true,
            LastRun: new DateTime(2026, 10, 12, 14, 0, 0), LastResult: 0,
            NextRun: new DateTime(2026, 10, 12, 15, 0, 0), Xml: EscrowTaskXml), culture);

        status.State.Should().Be("Ready");
        status.Summary.Should().Be("Scheduled task · Every hour · Last result 0");
        status.Details.Select(d => (d.Label, d.Value)).Should().Equal(
            ("Name", @"\CryptEscrow - BitLocker Key Sync"),
            ("Start type", "Enabled"),
            ("Status", "Ready"),
            ("Account", "SYSTEM"),
            ("Path and arguments", "\"C:\\Program Files\\Crypt\\checkin.exe\" escrow"),
            ("Triggers", "Every hour"),
            ("Last run", "10/12/2026 14:00"),
            ("Last result", "Succeeded"),
            ("Next run", "10/12/2026 15:00"));
    }

    [Fact]
    public void SummaryShowsAFailureCodeOrNeverRun()
    {
        var component = InstalledComponents.All[0];
        InstalledComponents.FromTask(component, new TaskSnapshot(3, true, new DateTime(2026, 10, 12), 1, null, EscrowTaskXml))
            .Summary.Should().Be("Scheduled task · Every hour · Last result 0x1");
        InstalledComponents.FromTask(component, new TaskSnapshot(3, true, null, 0x41303, null, EscrowTaskXml))
            .Summary.Should().Be("Scheduled task · Every hour · Never run");
    }

    [Fact]
    public void DisabledTaskReadsDisabledWhateverItsState()
    {
        var status = InstalledComponents.FromTask(InstalledComponents.All[0],
            new TaskSnapshot(3, Enabled: false, null, 0x41303, null, EscrowTaskXml));
        status.State.Should().Be("Disabled");
        status.Details.Should().Contain(new ComponentDetail("Start type", "Disabled"));
    }

    [Fact]
    public void AbsentTaskShowsOnlyNameAndNotInstalled()
    {
        var status = InstalledComponents.NotInstalled(InstalledComponents.All[0]);
        status.State.Should().Be("Not installed");
        status.Details.Select(d => d.Label).Should().Equal("Name", "Status");
    }

    [Fact]
    public void UnreadableTaskShowsUnknownForEveryField()
    {
        var status = InstalledComponents.Unknown(InstalledComponents.All[0]);
        status.State.Should().Be("Unknown");
        status.Summary.Should().Be("Scheduled task · Unknown");
        status.Details.Skip(1).Should().OnlyContain(d => d.Value == "Unknown");
        status.Details.Select(d => d.Label).Should().Equal(
            "Name", "Start type", "Status", "Account", "Path and arguments", "Triggers", "Last run", "Last result", "Next run");
    }
}

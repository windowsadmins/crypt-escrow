using System.Globalization;
using CryptEscrow.Gui;
using FluentAssertions;
using Xunit;

namespace CryptEscrow.Tests.Gui;

public class InstalledComponentsTests
{
    private static string Task(string triggers) => $"""
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <Triggers>{triggers}</Triggers>
        </Task>
        """.Trim();

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
        InstalledComponents.TriggersToWords(Task("""
            <TimeTrigger>
              <Repetition><Interval>PT1H</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
              <StartBoundary>2026-10-12T14:37:00</StartBoundary>
              <Enabled>true</Enabled>
            </TimeTrigger>
            """)).Should().Be("Every hour");

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
        var culture = CultureInfo.InvariantCulture;

        InstalledComponents.TaskResultWords(0, lastRun, culture).Should().Be("Succeeded · 10/12/2026 14:00");
        InstalledComponents.TaskResultWords(1, lastRun, culture).Should().Be("Failed (0x1) · 10/12/2026 14:00");
        InstalledComponents.TaskResultWords(unchecked((int)0x8007010B), lastRun, culture).Should().StartWith("Failed (0x8007010B)");
        InstalledComponents.TaskResultWords(0x41303, lastRun, culture).Should().Be("Never run");
        InstalledComponents.TaskResultWords(0, new DateTime(1899, 12, 30), culture).Should().Be("Never run");
        InstalledComponents.TaskResultWords(0, null, culture).Should().Be("Never run");
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

    [Fact]
    public void AbsentTaskShowsNotInstalled()
    {
        var status = InstalledComponents.NotInstalled(InstalledComponents.All[0]);
        status.State.Should().Be("Not installed");
        status.Caption.Should().Be("CryptEscrow - BitLocker Key Sync · Scheduled task");
    }
}

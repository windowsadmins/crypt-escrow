using System;
using System.IO;
using CryptEscrow;
using CryptEscrow.Services;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Serilog.Formatting.Display;
using Xunit;

namespace CryptEscrow.Tests;

/// <summary>
/// Where the log goes and what it records.
/// </summary>
/// <remarks>
/// The regression these pin down: the log path was hardcoded to a ProgramData root of
/// its own, while the installer wrote a config pointing somewhere else and the
/// troubleshooting docs quoted that other path. The configured value was never read --
/// the property was named Path, so the "file_path" key bound to nothing.
/// </remarks>
public class LoggingConfigurationTests
{
    private static readonly DateTime Stamp = new(2026, 9, 3, 14, 5, 9);

    [Fact]
    public void DefaultsUnderManagedEncryptionWithTheRestOfTheTool()
    {
        var expected = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "ManagedEncryption", "logs", "2026-09-03", "crypt-escrow.log");

        Assert.Equal(expected, Program.ResolveLogPath(null, Stamp));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void BlankConfiguredPathFallsBackToTheDefault(string configured)
    {
        Assert.Equal(Program.ResolveLogPath(null, Stamp), Program.ResolveLogPath(configured, Stamp));
    }

    [Fact]
    public void ConfiguredPathKeepsItsNameInsideTheDayDirectory()
    {
        var configured = Path.Combine("D:", "logs", "crypt.log");
        var expected = Path.Combine("D:", "logs", "2026-09-03", "crypt.log");

        Assert.Equal(expected, Program.ResolveLogPath(configured, Stamp));
    }

    [Fact]
    public void RetentionRemovesDayDirectoriesAndTheFlatLogsItReplaced()
    {
        var root = Path.Combine(Path.GetTempPath(), "crypt-escrow-retention-" + Guid.NewGuid().ToString("n"));
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "2026-07-01"));
            Directory.CreateDirectory(Path.Combine(root, "2026-09-03"));
            var stale = Path.Combine(root, "crypt-escrow20260701.log");
            File.WriteAllText(stale, "old\n");
            File.SetLastWriteTime(stale, new DateTime(2026, 7, 1));

            var removed = Program.PruneLogDirectory(root, 30, Stamp);

            Assert.Equal(2, removed);
            Assert.Equal(new[] { "2026-09-03" }, Directory.GetDirectories(root).Select(Path.GetFileName).ToArray());
            Assert.Empty(Directory.GetFiles(root));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }

    [Theory]
    [InlineData("Verbose", LogEventLevel.Verbose)]
    [InlineData("debug", LogEventLevel.Debug)]
    [InlineData("INFO", LogEventLevel.Information)]
    [InlineData("Information", LogEventLevel.Information)]
    [InlineData("warn", LogEventLevel.Warning)]
    [InlineData("WARNING", LogEventLevel.Warning)]
    [InlineData("Error", LogEventLevel.Error)]
    [InlineData("fatal", LogEventLevel.Fatal)]
    public void LevelNamesMapOntoSerilog(string configured, LogEventLevel expected)
    {
        Assert.Equal(expected, Program.ParseLevel(configured));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("nonsense")]
    public void UnrecognisedLevelStaysAtInformationRatherThanSilencingTheLog(string? configured)
    {
        Assert.Equal(LogEventLevel.Information, Program.ParseLevel(configured));
    }

    [Theory]
    [InlineData("INFO", false, LogEventLevel.Information)]
    [InlineData("INFO", true, LogEventLevel.Debug)]
    [InlineData("ERROR", true, LogEventLevel.Debug)]
    [InlineData("VERBOSE", true, LogEventLevel.Verbose)]
    [InlineData(null, true, LogEventLevel.Debug)]
    public void VerboseLowersTheLevelToDebugWithoutRaisingAQuieterOne(
        string? configured, bool verbose, LogEventLevel expected)
    {
        Assert.Equal(expected, Program.ResolveLevel(configured, verbose));
    }

    [Theory]
    [InlineData(new[] { "escrow", "-v" }, true)]
    [InlineData(new[] { "--verbose", "verify" }, true)]
    [InlineData(new[] { "escrow", "--force" }, false)]
    [InlineData(new string[0], false)]
    public void VerboseFlagIsReadFromTheRawArguments(string[] args, bool expected)
    {
        Assert.Equal(expected, Program.IsVerbose(args));
    }

    [Theory]
    [InlineData(LogEventLevel.Verbose, "DEBUG")]
    [InlineData(LogEventLevel.Debug, "DEBUG")]
    [InlineData(LogEventLevel.Information, "INFO ")]
    [InlineData(LogEventLevel.Warning, "WARN ")]
    [InlineData(LogEventLevel.Error, "ERROR")]
    [InlineData(LogEventLevel.Fatal, "ERROR")]
    public void LevelNamesArePaddedToFiveCharacters(LogEventLevel level, string expected)
    {
        Assert.Equal(expected, LevelNameEnricher.For(level));
        Assert.Equal(5, LevelNameEnricher.For(level).Length);
    }

    [Theory]
    [InlineData(LogEventLevel.Information, "INFO  key escrowed")]
    [InlineData(LogEventLevel.Warning, "WARN  key escrowed")]
    [InlineData(LogEventLevel.Error, "ERROR key escrowed")]
    public void FileLinesReadTimestampLevelMessage(LogEventLevel level, string expectedTail)
    {
        var sink = new CapturingSink(Program.FileTemplate);
        var logger = new LoggerConfiguration()
            .MinimumLevel.Verbose()
            .Enrich.With<LevelNameEnricher>()
            .WriteTo.Sink(sink)
            .CreateLogger();

        logger.Write(level, "key {Action}", "escrowed");

        var line = Assert.Single(sink.Lines).TrimEnd();
        Assert.Matches(@"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] " + System.Text.RegularExpressions.Regex.Escape(expectedTail) + "$", line);
    }

    private sealed class CapturingSink(string template) : ILogEventSink
    {
        private readonly MessageTemplateTextFormatter _formatter = new(template);

        public List<string> Lines { get; } = [];

        public void Emit(LogEvent logEvent)
        {
            var writer = new StringWriter();
            _formatter.Format(logEvent, writer);
            Lines.Add(writer.ToString());
        }
    }
}

using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CryptEscrow.Gui;
using CryptEscrow.Services;

namespace CryptEscrow.App.ViewModels;

/// <summary>
/// ViewModel for the Logs tab: the CLI's log folder, one session per day, newest first.
/// Lines are coloured by level and pass through <see cref="RecoveryKeyRedactor"/>.
/// </summary>
public partial class LogsViewModel : ObservableObject
{
    public string LogDirectory { get; } = LogLayout.ResolveLogDirectory(ConfigService.GetLoggingConfig().FilePath);

    public ObservableCollection<LogSession> LogFiles { get; } = [];

    [ObservableProperty] private LogSession? _selectedLog;
    [ObservableProperty] private string _logContent = string.Empty;
    [ObservableProperty] private string _filterText = string.Empty;

    public IEnumerable<LogLine> FilteredLines
    {
        get
        {
            var lines = LogContent.Split('\n')
                .Select(l => l.TrimEnd('\r'))
                .Where(l => !string.IsNullOrWhiteSpace(l))
                .Select(l => new LogLine(l, LogSessions.Classify(l)));
            return string.IsNullOrWhiteSpace(FilterText)
                ? lines
                : lines.Where(l => l.Text.Contains(FilterText, StringComparison.OrdinalIgnoreCase));
        }
    }

    public record LogLine(string Text, LogLineLevel Level);

    public void Refresh()
    {
        var previous = SelectedLog?.Path;
        LogFiles.Clear();
        foreach (var session in LogSessions.List(LogDirectory))
            LogFiles.Add(session);

        SelectedLog = LogFiles.FirstOrDefault(f => f.Path == previous) ?? LogFiles.FirstOrDefault();
    }

    partial void OnSelectedLogChanged(LogSession? value)
    {
        if (value is null)
        {
            LogContent = string.Empty;
            return;
        }

        try
        {
            LogContent = RecoveryKeyRedactor.Redact(LogSessions.ReadShared(value.Path));
        }
        catch
        {
            LogContent = "Unable to read log file.";
        }
    }

    partial void OnLogContentChanged(string value) => OnPropertyChanged(nameof(FilteredLines));
    partial void OnFilterTextChanged(string value) => OnPropertyChanged(nameof(FilteredLines));

    public void OpenInEditor()
    {
        if (SelectedLog is null) return;
        Process.Start(new ProcessStartInfo(SelectedLog.Path) { UseShellExecute = true });
    }

    public void OpenFolder()
    {
        if (!Directory.Exists(LogDirectory)) return;
        Process.Start(new ProcessStartInfo(LogDirectory) { UseShellExecute = true });
    }
}

using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CryptEscrow.Gui;
using CryptEscrow.Services;
using Microsoft.UI.Dispatching;

namespace CryptEscrow.App.ViewModels;

/// <summary>
/// ViewModel for the Run tab. Launches the CLI elevated for one fixed mode and streams the
/// lines it writes to its log. An elevated process's output cannot be redirected to this
/// unelevated one, so the log is the stream. Every line passes through
/// <see cref="RecoveryKeyRedactor"/> before it is shown.
/// </summary>
public partial class RunViewModel : ObservableObject
{
    public const string CliExecutableName = "checkin.exe";

    private Process? _cliProcess;
    private CancellationTokenSource? _cts;
    private readonly DispatcherQueue _dispatcher;

    public RunViewModel(DispatcherQueue dispatcher)
    {
        _dispatcher = dispatcher;
    }

    // ── Observable State ─────────────────────────────────────────

    [ObservableProperty] private bool _isRunning;
    [ObservableProperty] private int? _lastExitCode;
    [ObservableProperty] private bool _showDebug;
    [ObservableProperty] private int _errorCount;
    [ObservableProperty] private RunMode _mode = RunMode.EscrowNow;

    public ObservableCollection<OutputLine> OutputLines { get; } = [];

    public IEnumerable<OutputLine> FilteredLines =>
        ShowDebug ? OutputLines : OutputLines.Where(l => l.Level != LogLineLevel.Debug);

    public record OutputLine(string Text, LogLineLevel Level);

    // ── Run ──────────────────────────────────────────────────────

    public async Task RunAsync()
    {
        if (IsRunning) return;

        IsRunning = true;
        LastExitCode = null;
        ErrorCount = 0;
        OutputLines.Clear();
        OnPropertyChanged(nameof(FilteredLines));

        _cts = new CancellationTokenSource();

        var cliPath = FindCliExecutable();
        if (cliPath is null)
        {
            AppendLine($"[ERROR] {CliExecutableName} not found beside the app.", LogLineLevel.Error);
            IsRunning = false;
            return;
        }

        var args = RunModes.Arguments(Mode, ConfigService.GetCleanupOldProtectors()).ToList();
        if (ShowDebug)
            args.Add("--verbose");

        AppendLine($"[i] {RunModes.Label(Mode)}: checkin {string.Join(" ", args)}", LogLineLevel.Info);

        // The day's log is shared by every run that day: stream only what this run adds.
        var logPath = LogLayout.ResolveLogPath(ConfigService.GetLoggingConfig().FilePath, DateTime.Now);
        var startOffset = FileLength(logPath);

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = cliPath,
                UseShellExecute = true,
                Verb = "runas",
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            foreach (var arg in args)
                startInfo.ArgumentList.Add(arg);

            _cliProcess = Process.Start(startInfo);
            if (_cliProcess is null)
            {
                AppendLine("[ERROR] Could not start the escrow tool.", LogLineLevel.Error);
                return;
            }

            AppendLine($"[i] Started (PID {_cliProcess.Id})", LogLineLevel.Debug);

            var tailTask = TailLogFileAsync(logPath, startOffset, _cts.Token);

            await _cliProcess.WaitForExitAsync(_cts.Token);
            LastExitCode = _cliProcess.ExitCode;

            // Give the log a moment to flush its last lines.
            await Task.Delay(1000, CancellationToken.None);
            await _cts.CancelAsync();

            try { await tailTask; } catch (OperationCanceledException) { }
        }
        catch (OperationCanceledException)
        {
            AppendLine("[WARNING] Stopped.", LogLineLevel.Warning);
        }
        catch (Exception ex) when (PrefsElevation.IsElevationCancelled(ex))
        {
            AppendLine("[ERROR] Administrator approval was declined; nothing ran.", LogLineLevel.Error);
        }
        catch (Exception ex)
        {
            AppendLine($"[ERROR] {RecoveryKeyRedactor.Redact(ex.Message)}", LogLineLevel.Error);
        }
        finally
        {
            IsRunning = false;
            _cliProcess?.Dispose();
            _cliProcess = null;
        }
    }

    public void Stop()
    {
        if (!IsRunning) return;

        try
        {
            _cts?.Cancel();
            if (_cliProcess is { HasExited: false })
                _cliProcess.Kill(entireProcessTree: true);
        }
        catch
        {
            // An elevated run cannot always be stopped from an unelevated app.
        }

        LastExitCode = null;
    }

    public void Clear()
    {
        OutputLines.Clear();
        LastExitCode = null;
        OnPropertyChanged(nameof(FilteredLines));
    }

    // ── Log Tail ─────────────────────────────────────────────────

    private async Task TailLogFileAsync(string logPath, long position, CancellationToken ct)
    {
        for (int i = 0; i < 30 && !File.Exists(logPath) && !ct.IsCancellationRequested; i++)
            await Task.Delay(500, ct);

        if (!File.Exists(logPath))
        {
            AppendLine("[!] The run's log did not appear; output cannot stream.", LogLineLevel.Warning);
            return;
        }

        AppendLine($"[i] Streaming {logPath}", LogLineLevel.Debug);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (fs.Length > position)
                {
                    fs.Position = position;
                    using var reader = new StreamReader(fs);
                    string? line;
                    while ((line = await reader.ReadLineAsync(ct)) is not null)
                    {
                        if (!string.IsNullOrWhiteSpace(line))
                            AppendLine(line, LogSessions.Classify(line));
                    }
                    position = fs.Position;
                }
            }
            catch (IOException) { }

            await Task.Delay(300, ct);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────

    private void AppendLine(string text, LogLineLevel level)
    {
        var safe = RecoveryKeyRedactor.Redact(text);
        _dispatcher.TryEnqueue(() =>
        {
            OutputLines.Add(new OutputLine(safe, level));
            OnPropertyChanged(nameof(FilteredLines));
            if (level == LogLineLevel.Error)
                ErrorCount++;
        });
    }

    private static long FileLength(string path)
    {
        try { return File.Exists(path) ? new FileInfo(path).Length : 0; } catch { return 0; }
    }

    /// <summary>The CLI installs beside the app.</summary>
    internal static string? FindCliExecutable()
    {
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, CliExecutableName),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Crypt", CliExecutableName),
        };
        return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists);
    }

    partial void OnShowDebugChanged(bool value) => OnPropertyChanged(nameof(FilteredLines));
}

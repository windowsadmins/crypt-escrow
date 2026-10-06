using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;
using CryptEscrow.App.ViewModels;
using CryptEscrow.Gui;

namespace CryptEscrow.App.Views;

public sealed partial class RunPage : Page
{
    private readonly RunViewModel _vm;

    public RunPage()
    {
        InitializeComponent();

        _vm = new RunViewModel(DispatcherQueue.GetForCurrentThread());
        _vm.PropertyChanged += OnViewModelPropertyChanged;
        _vm.OutputLines.CollectionChanged += (_, _) => ScrollToBottom();

        foreach (var mode in RunModes.All)
            ModePicker.Items.Add(RunModes.Label(mode));
        ModePicker.SelectedIndex = 0;
    }

    // ── Button Handlers ─────────────────────────────────────────

    private void ModePicker_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ModePicker.SelectedIndex < 0) return;
        _vm.Mode = RunModes.All[ModePicker.SelectedIndex];
        ModeDescription.Text = RunModes.Description(_vm.Mode);
        RunText.Text = RunModes.Label(_vm.Mode);
    }

    private async void RunButton_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.IsRunning)
        {
            _vm.Stop();
            return;
        }

        if (RunModes.NeedsConfirmation(_vm.Mode) && !await ConfirmAsync(_vm.Mode))
            return;

        await _vm.RunAsync();
    }

    private async Task<bool> ConfirmAsync(RunMode mode)
    {
        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = $"{RunModes.Label(mode)}?",
            Content = RunModes.Description(mode),
            PrimaryButtonText = RunModes.Label(mode),
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close
        };
        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    private void ClearButton_Click(object sender, RoutedEventArgs e) => _vm.Clear();

    private void DebugToggle_Changed(object sender, RoutedEventArgs e)
        => _vm.ShowDebug = DebugToggle.IsChecked ?? false;

    // ── UI State Sync ────────────────────────────────────────────

    private void OnViewModelPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        switch (e.PropertyName)
        {
            case nameof(RunViewModel.IsRunning):
                UpdateRunningState();
                break;
            case nameof(RunViewModel.LastExitCode):
                UpdateStatusIndicator();
                UpdateResultBanner();
                break;
            case nameof(RunViewModel.FilteredLines):
                UpdateConsoleItems();
                break;
        }
    }

    private void UpdateRunningState()
    {
        ModePicker.IsEnabled = !_vm.IsRunning;
        if (_vm.IsRunning)
        {
            RunIcon.Glyph = ""; // Stop icon
            RunText.Text = "Stop";
            RunButton.Background = new SolidColorBrush(Microsoft.UI.Colors.IndianRed);
            RunningProgress.IsActive = true;
            RunningLabel.Visibility = Visibility.Visible;
            ClearButton.Visibility = Visibility.Collapsed;
            ResultBanner.IsOpen = false;
        }
        else
        {
            RunIcon.Glyph = ""; // Play icon
            RunText.Text = RunModes.Label(_vm.Mode);
            RunButton.ClearValue(Button.BackgroundProperty);
            RunningProgress.IsActive = false;
            RunningLabel.Visibility = Visibility.Collapsed;
            ClearButton.Visibility = _vm.OutputLines.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        }
    }

    private void UpdateStatusIndicator()
    {
        if (_vm.LastExitCode is null)
        {
            StatusPanel.Visibility = Visibility.Collapsed;
            return;
        }

        StatusPanel.Visibility = Visibility.Visible;
        var ok = _vm.LastExitCode == 0;
        var brush = new SolidColorBrush(ok ? Microsoft.UI.Colors.ForestGreen : Microsoft.UI.Colors.IndianRed);
        StatusIcon.Glyph = ok ? "" : "";
        StatusIcon.Foreground = brush;
        StatusText.Text = ok ? "Completed successfully" : $"Failed (exit code {_vm.LastExitCode})";
        StatusText.Foreground = brush;
    }

    private void UpdateConsoleItems()
    {
        ConsoleOutput.Blocks.Clear();
        foreach (var line in _vm.FilteredLines)
        {
            var paragraph = new Paragraph { Margin = new Thickness(0, 1, 0, 1), Foreground = BrushForLevel(line.Level) };
            paragraph.Inlines.Add(new Run { Text = line.Text });
            ConsoleOutput.Blocks.Add(paragraph);
        }
    }

    private void ScrollToBottom()
    {
        DispatcherQueue.TryEnqueue(() =>
            ConsoleScroller.ChangeView(null, ConsoleScroller.ScrollableHeight, null));
    }

    private void UpdateResultBanner()
    {
        if (_vm.LastExitCode is null)
        {
            ResultBanner.IsOpen = false;
            return;
        }

        ResultBanner.IsOpen = true;
        if (_vm.LastExitCode == 0)
        {
            ResultBanner.Severity = InfoBarSeverity.Success;
            ResultBanner.Title = $"{RunModes.Label(_vm.Mode)} completed";
            ResultBanner.Message = "";
        }
        else
        {
            ResultBanner.Severity = InfoBarSeverity.Error;
            ResultBanner.Title = $"{RunModes.Label(_vm.Mode)} failed with exit code {_vm.LastExitCode}";
            ResultBanner.Message = _vm.ErrorCount > 0
                ? $"{_vm.ErrorCount} error{(_vm.ErrorCount == 1 ? "" : "s")} in the output"
                : "Check the output for details";
        }
    }

    internal static SolidColorBrush BrushForLevel(LogLineLevel level) => level switch
    {
        LogLineLevel.Error   => new SolidColorBrush(Microsoft.UI.Colors.IndianRed),
        LogLineLevel.Warning => new SolidColorBrush(Microsoft.UI.Colors.Goldenrod),
        LogLineLevel.Debug   => new SolidColorBrush(Windows.UI.Color.FromArgb(204, 128, 128, 128)),
        _ => (SolidColorBrush)Application.Current.Resources["TextFillColorPrimaryBrush"],
    };
}

using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Microsoft.UI.Xaml.Navigation;
using CryptEscrow.App.ViewModels;
using CryptEscrow.Gui;

namespace CryptEscrow.App.Views;

/// <summary>
/// The Prefs tab. The cards are built from <see cref="SettingsCatalog"/>, so every setting
/// the CLI reads appears here with the same lock and source rules. A field set by policy is
/// disabled, and one line above the cards says so for all of them.
/// </summary>
public sealed partial class PrefsPage : Page
{
    public PrefsViewModel ViewModel { get; } = new();

    public PrefsPage()
    {
        InitializeComponent();

        var iconPath = System.IO.Path.Combine(AppContext.BaseDirectory, "Assets", "ManagedEncryption.png");
        if (System.IO.File.Exists(iconPath))
            AppIcon.Source = new BitmapImage(new Uri(iconPath));

        VersionText.Text = ViewModel.VersionDisplay;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        Reload();
        _ = RefreshServicesAsync();
    }

    private void RefreshServices_Click(object sender, RoutedEventArgs e) => _ = RefreshServicesAsync();

    private async Task RefreshServicesAsync()
    {
        RefreshServicesButton.IsEnabled = false;
        ServicesList.ItemsSource = ViewModel.Components;
        try
        {
            await ViewModel.LoadComponentsAsync();
        }
        finally
        {
            ServicesList.ItemsSource = ViewModel.Components;
            RefreshServicesButton.IsEnabled = true;
            ServicesAccessHint.Visibility = ViewModel.ServicesNeedAdmin ? Visibility.Visible : Visibility.Collapsed;
        }
    }

    // ── Save ────────────────────────────────────────────────────

    private async void SaveButton_Click(object sender, RoutedEventArgs e)
    {
        SaveButton.IsEnabled = DiscardButton.IsEnabled = false;
        // A declined UAC prompt or a failure keeps the edits on screen and pending.
        if (await ViewModel.SaveAsync())
            Reload();
        else
            UpdateSaveBar();
        SaveButton.IsEnabled = DiscardButton.IsEnabled = true;
    }

    private void DiscardButton_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.DiscardPending();
        Reload();
    }

    private void UpdateSaveBar()
    {
        SaveButtons.Visibility = ViewModel.HasPendingChanges ? Visibility.Visible : Visibility.Collapsed;
        SaveStatusText.Text = ViewModel.HasPendingChanges && !ViewModel.HasSaveMessage
            ? "You have unsaved changes."
            : ViewModel.SaveMessage;
        SaveStatusText.Foreground = (Brush)Application.Current.Resources[
            ViewModel.SaveFailed && ViewModel.HasSaveMessage ? "SystemFillColorCriticalBrush" : "TextFillColorSecondaryBrush"];
        SaveBar.Visibility = ViewModel.HasPendingChanges || ViewModel.HasSaveMessage ? Visibility.Visible : Visibility.Collapsed;
    }

    // ── Cards ───────────────────────────────────────────────────

    private void Reload()
    {
        ViewModel.Load();
        Fill(ConnectionCard, SettingsCatalog.Connection, "");
        Fill(EscrowCard, SettingsCatalog.Escrow, "");
        Fill(AuthenticationCard, SettingsCatalog.Authentication, "");
        Fill(LoggingCard, SettingsCatalog.Logging, "");
        PolicyBanner.Visibility = ViewModel.HasPolicySettings ? Visibility.Visible : Visibility.Collapsed;

        UpdateSaveBar();
    }

    private void Fill(StackPanel card, string group, string glyph)
    {
        card.Children.Clear();

        var header = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10, Margin = new Thickness(0, 0, 0, 4) };
        header.Children.Add(new FontIcon
        {
            Glyph = glyph,
            FontSize = 20,
            VerticalAlignment = VerticalAlignment.Center,
            Foreground = (Brush)Application.Current.Resources["AccentTextFillColorPrimaryBrush"]
        });
        header.Children.Add(new TextBlock
        {
            Text = group,
            Style = (Style)Application.Current.Resources["SubtitleTextBlockStyle"],
            VerticalAlignment = VerticalAlignment.Center
        });
        card.Children.Add(header);

        foreach (var state in ViewModel.InGroup(group))
            AddField(card, state);
    }

    private void AddField(StackPanel card, SettingState state)
    {
        var definition = state.Definition;
        var editable = ViewModel.CanEdit(state);

        if (definition.Kind != SettingKind.Toggle)
            card.Children.Add(Caption(definition.Label, primary: true, top: 4));

        switch (definition.Kind)
        {
            case SettingKind.Toggle:
                var toggle = new ToggleSwitch
                {
                    OnContent = definition.Label,
                    OffContent = definition.Label,
                    IsOn = state.ToggleValue,
                    IsEnabled = editable
                };
                toggle.Toggled += (_, _) => Stage(state, toggle.IsOn ? "true" : "false");
                card.Children.Add(toggle);
                break;

            case SettingKind.Number:
                var number = new NumberBox
                {
                    Value = double.TryParse(state.FieldValue, out var n) ? n : double.NaN,
                    PlaceholderText = state.EffectiveValue,
                    SpinButtonPlacementMode = NumberBoxSpinButtonPlacementMode.Compact,
                    Minimum = 0,
                    Width = 140,
                    HorizontalAlignment = HorizontalAlignment.Left,
                    IsEnabled = editable
                };
                number.ValueChanged += (_, args) =>
                {
                    var value = double.IsNaN(args.NewValue) ? null : ((int)args.NewValue).ToString();
                    Stage(state, value);
                };
                card.Children.Add(number);
                break;

            case SettingKind.Choice:
                var combo = new ComboBox { IsEnabled = editable, MinWidth = 200 };
                combo.Items.Add("(not set)");
                foreach (var choice in definition.Choices ?? [])
                    combo.Items.Add(choice);
                var selected = definition.Choices?.ToList().FindIndex(c =>
                    string.Equals(c, state.FieldValue, StringComparison.OrdinalIgnoreCase)) ?? -1;
                combo.SelectedIndex = selected + 1;
                combo.SelectionChanged += (_, _) =>
                {
                    var value = combo.SelectedIndex <= 0 ? null : (string)combo.SelectedItem;
                    Stage(state, value);
                };
                card.Children.Add(combo);
                break;

            case SettingKind.Secret:
                card.Children.Add(Caption(state.SecretStatus(ViewModel.IsElevated), primary: false));
                if (editable)
                {
                    var row = new Grid { ColumnSpacing = 4 };
                    row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                    row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                    var secret = new PasswordBox { PlaceholderText = "Enter a new value to replace" };
                    secret.LostFocus += (_, _) =>
                    {
                        if (!string.IsNullOrEmpty(secret.Password)) Stage(state, secret.Password);
                    };
                    // Unelevated, whether a secret is saved cannot be read, so Clear is always offered.
                    var clear = new Button { Content = "Clear", IsEnabled = !ViewModel.IsElevated || state.MachineValue is not null };
                    Grid.SetColumn(clear, 1);
                    clear.Click += (_, _) => Stage(state, null);
                    row.Children.Add(secret);
                    row.Children.Add(clear);
                    card.Children.Add(row);
                }
                break;

            default:
                var text = new TextBox
                {
                    Text = state.FieldValue ?? "",
                    PlaceholderText = definition.Placeholder ?? "",
                    IsEnabled = editable
                };
                text.LostFocus += (_, _) =>
                {
                    var value = string.IsNullOrWhiteSpace(text.Text) ? null : text.Text.Trim();
                    Stage(state, value);
                };
                card.Children.Add(text);
                break;
        }

        // A managed field gets no caption: it is disabled, and the policy banner covers it.
        if (!state.IsManaged && definition.Kind != SettingKind.Secret && state.MachineValue is null
            && !string.IsNullOrEmpty(state.SourceCaption))
            card.Children.Add(Caption(state.SourceCaption, primary: false));

        if (definition.Note is { } note)
            card.Children.Add(Caption(note, primary: false));
    }

    /// <summary>Holds an edit as pending until Save; the cards keep showing it.</summary>
    private void Stage(SettingState state, string? value)
    {
        ViewModel.SetPending(state, value);
        if (ViewModel.HasSaveMessage && !ViewModel.SaveFailed)
            ViewModel.SaveMessage = "";
        UpdateSaveBar();
    }

    private static TextBlock Caption(string text, bool primary, double top = 0) => new()
    {
        Text = text,
        Style = (Style)Application.Current.Resources["CaptionTextBlockStyle"],
        TextWrapping = TextWrapping.WrapWholeWords,
        Margin = new Thickness(0, top, 0, 0),
        Foreground = primary
            ? (Brush)Application.Current.Resources["TextFillColorPrimaryBrush"]
            : (Brush)Application.Current.Resources["TextFillColorTertiaryBrush"]
    };
}

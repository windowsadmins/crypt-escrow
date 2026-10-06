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
/// the CLI reads appears here with the same lock and source rules.
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
        ReadOnlyBanner.Visibility = ViewModel.IsReadOnly ? Visibility.Visible : Visibility.Collapsed;
        ElevatedNote.Visibility = ViewModel.IsElevated ? Visibility.Visible : Visibility.Collapsed;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        Reload();
    }

    private void UnlockButton_Click(object sender, RoutedEventArgs e)
    {
        // Once the elevated copy has started (UAC accepted), this read-only instance closes.
        // A cancelled UAC prompt returns false and the tab simply stays read-only.
        if (ViewModel.TryRelaunchElevated())
        {
            Application.Current.Exit();
            return;
        }
        UnlockErrorText.Text = ViewModel.UnlockError;
        UnlockErrorText.Visibility = ViewModel.HasUnlockError ? Visibility.Visible : Visibility.Collapsed;
    }

    // ── Cards ───────────────────────────────────────────────────

    private void Reload()
    {
        ViewModel.Load();
        Fill(ConnectionCard, SettingsCatalog.Connection, "");
        Fill(EscrowCard, SettingsCatalog.Escrow, "");
        Fill(AuthenticationCard, SettingsCatalog.Authentication, "");
        Fill(LoggingCard, SettingsCatalog.Logging, "");

        SaveStatusText.Text = ViewModel.SaveMessage;
        SaveStatusText.Visibility = ViewModel.HasSaveMessage ? Visibility.Visible : Visibility.Collapsed;
        SaveStatusText.Foreground = (Brush)Application.Current.Resources[
            ViewModel.SaveFailed ? "SystemFillColorCriticalBrush" : "TextFillColorSecondaryBrush"];
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
                toggle.Toggled += (_, _) => SaveLater(state, toggle.IsOn ? "true" : "false");
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
                    if (value != state.FieldValue) SaveLater(state, value);
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
                    if (!string.Equals(value, state.FieldValue, StringComparison.OrdinalIgnoreCase)) SaveLater(state, value);
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
                        if (!string.IsNullOrEmpty(secret.Password)) SaveLater(state, secret.Password);
                    };
                    var clear = new Button { Content = "Clear", IsEnabled = state.MachineValue is not null };
                    Grid.SetColumn(clear, 1);
                    clear.Click += (_, _) => SaveLater(state, null);
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
                    if (value != state.FieldValue) SaveLater(state, value);
                };
                card.Children.Add(text);
                break;
        }

        if (state.IsManaged)
            card.Children.Add(PolicyLock());
        else if (definition.Kind != SettingKind.Secret && state.MachineValue is null)
            card.Children.Add(Caption(state.SourceCaption, primary: false));

        if (definition.Note is { } note)
            card.Children.Add(Caption(note, primary: false));
    }

    /// <summary>Saves after the current event finishes, then rebuilds the cards.</summary>
    private void SaveLater(SettingState state, string? value) =>
        DispatcherQueue.TryEnqueue(() =>
        {
            ViewModel.Save(state, value);
            Reload();
        });

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

    private static StackPanel PolicyLock()
    {
        var panel = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 4 };
        var secondary = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"];
        panel.Children.Add(new FontIcon { Glyph = "", FontSize = 12, Foreground = secondary });
        panel.Children.Add(new TextBlock
        {
            Text = "Managed by Policy",
            Style = (Style)Application.Current.Resources["CaptionTextBlockStyle"],
            Foreground = secondary
        });
        return panel;
    }
}

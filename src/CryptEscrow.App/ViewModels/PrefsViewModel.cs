using System.Reflection;
using CommunityToolkit.Mvvm.ComponentModel;
using CryptEscrow.Gui;

namespace CryptEscrow.App.ViewModels;

/// <summary>
/// ViewModel for the Prefs tab. Settings live in HKLM, so the tab is read-only unless this
/// process is elevated; Unlock relaunches the app elevated on this tab. A field set by
/// policy shows the policy value and stays locked. Secrets are never read into the view:
/// once elevated, the tab only says whether one is saved.
/// </summary>
public partial class PrefsViewModel : ObservableObject
{
    // ── Elevation State ─────────────────────────────────────────

    /// <summary>True when this process can write HKLM (elevated administrator token).</summary>
    public bool IsElevated { get; } = PrefsElevation.IsProcessElevated();

    public bool IsReadOnly => !IsElevated;

    [ObservableProperty] private string _unlockError = "";

    public bool HasUnlockError => !string.IsNullOrEmpty(UnlockError);

    partial void OnUnlockErrorChanged(string value) => OnPropertyChanged(nameof(HasUnlockError));

    // ── Settings ────────────────────────────────────────────────

    public IReadOnlyList<SettingState> Settings { get; private set; } = [];

    public IEnumerable<SettingState> InGroup(string group) => Settings.Where(s => s.Definition.Group == group);

    public bool CanEdit(SettingState state) => PrefsElevation.CanEdit(IsElevated, state.IsManaged);

    // ── Save Status ─────────────────────────────────────────────

    [ObservableProperty] private string _saveMessage = "";
    [ObservableProperty] private bool _saveFailed;

    public bool HasSaveMessage => !string.IsNullOrEmpty(SaveMessage);

    partial void OnSaveMessageChanged(string value) => OnPropertyChanged(nameof(HasSaveMessage));

    // ── Version Info ────────────────────────────────────────────

    public string VersionDisplay => $"Version {AppVersion}";

    // The version the release stamps from its tag, zero-padded as the tag is; the
    // "+<commit>" the SDK appends is dropped.
    public static string AppVersion =>
        typeof(PrefsViewModel).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            .Split('+')[0]
        ?? typeof(PrefsViewModel).Assembly.GetName().Version?.ToString()
        ?? "unknown";

    // ── Load / Save ─────────────────────────────────────────────

    public void Load()
    {
        Settings = SettingsCatalog.Load();
        OnPropertyChanged(nameof(Settings));
    }

    /// <summary>
    /// Writes one field to the machine settings key. An empty value removes the saved
    /// value. Never called while read-only, and refused for a managed field.
    /// </summary>
    public bool Save(SettingState state, string? value)
    {
        if (!CanEdit(state))
            return false;

        try
        {
            SettingsCatalog.Save(state.Definition.Name, value);
            SaveFailed = false;
            SaveMessage = state.Definition.Kind == SettingKind.Secret
                ? $"Saved {state.Definition.Label}"
                : string.IsNullOrWhiteSpace(value)
                    ? $"Cleared {state.Definition.Label}"
                    : $"Saved {state.Definition.Label}";
            Load();
            return true;
        }
        catch (Exception ex)
        {
            SaveFailed = true;
            SaveMessage = $"Could not save {state.Definition.Label}: {ex.Message}";
            return false;
        }
    }

    /// <summary>
    /// Relaunches this app elevated through UAC, opening on the Prefs tab. Returns true when
    /// the elevated instance started, so the caller can close this one. A cancelled UAC
    /// prompt returns false quietly and leaves the tab read-only.
    /// </summary>
    public bool TryRelaunchElevated()
    {
        UnlockError = "";
        try
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exe))
            {
                UnlockError = "Could not find the app's own executable to relaunch.";
                return false;
            }

            using var process = System.Diagnostics.Process.Start(PrefsElevation.BuildElevatedRelaunch(exe));
            return process is not null;
        }
        catch (Exception ex) when (PrefsElevation.IsElevationCancelled(ex))
        {
            return false;
        }
        catch (Exception ex)
        {
            UnlockError = $"Could not relaunch as administrator: {ex.Message}";
            return false;
        }
    }
}

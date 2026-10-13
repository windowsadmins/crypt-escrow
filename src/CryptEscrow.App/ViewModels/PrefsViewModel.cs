using System.Diagnostics;
using System.Reflection;
using CommunityToolkit.Mvvm.ComponentModel;
using CryptEscrow.App.Services;
using CryptEscrow.Gui;

namespace CryptEscrow.App.ViewModels;

/// <summary>
/// ViewModel for the Prefs tab. Every setting policy does not set can be edited; edits are
/// held as pending until Save writes them to HKLM, asking for administrator approval then
/// when the app is not already elevated. A field set by policy shows the policy value and
/// stays disabled, under one banner for the tab. Secrets are never read into the view.
/// </summary>
public partial class PrefsViewModel : ObservableObject
{
    /// <summary>True when this process can write HKLM directly (elevated administrator token).</summary>
    public bool IsElevated { get; } = PrefsElevation.IsProcessElevated();

    // ── Settings ────────────────────────────────────────────────

    public IReadOnlyList<SettingState> Settings { get; private set; } = [];

    public IEnumerable<SettingState> InGroup(string group) => Settings.Where(s => s.Definition.Group == group);

    public bool CanEdit(SettingState state) => PrefsElevation.CanEdit(state.IsManaged);

    /// <summary>True when any setting comes from the policy key; shows the policy banner.</summary>
    public bool HasPolicySettings => Settings.Any(s => s.IsManaged);

    // ── Pending Changes ─────────────────────────────────────────

    private readonly Dictionary<string, string?> _pending = new(StringComparer.OrdinalIgnoreCase);

    public bool HasPendingChanges => _pending.Count > 0;

    [ObservableProperty] private bool _isSaving;

    /// <summary>
    /// Records an edit. A value equal to what is saved drops the pending change; a secret
    /// is always pending, since the saved one is never read.
    /// </summary>
    public void SetPending(SettingState state, string? value)
    {
        if (!CanEdit(state))
            return;
        var name = state.Definition.Name;
        if (state.Definition.Kind != SettingKind.Secret && string.Equals(value, state.FieldValue, StringComparison.Ordinal))
            _pending.Remove(name);
        else
            _pending[name] = value;
        OnPropertyChanged(nameof(HasPendingChanges));
    }

    public void DiscardPending()
    {
        _pending.Clear();
        SaveMessage = "";
        OnPropertyChanged(nameof(HasPendingChanges));
    }

    // ── Services ────────────────────────────────────────────────

    /// <summary>The scheduled task the installer creates, and how it is doing.</summary>
    public bool HasComponents => InstalledComponents.All.Count > 0;

    public IReadOnlyList<ComponentStatus> Components { get; private set; } =
        InstalledComponents.All.Select(InstalledComponents.Checking).ToList();

    /// <summary>A task the user cannot read: SYSTEM tasks are readable only by administrators.</summary>
    public bool ServicesNeedAdmin => !IsElevated && Components.Any(c => c.State == InstalledComponents.UnknownText);

    public async Task LoadComponentsAsync()
    {
        Components = await ComponentStatusReader.ReadAllAsync();
        OnPropertyChanged(nameof(Components));
        OnPropertyChanged(nameof(ServicesNeedAdmin));
    }

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
        OnPropertyChanged(nameof(HasPolicySettings));
    }

    /// <summary>
    /// Writes the pending changes to the machine settings key: directly when elevated,
    /// otherwise through an elevated, windowless copy of this app. Returns true when they
    /// were saved; on failure, or when UAC is declined, the changes stay pending.
    /// </summary>
    public async Task<bool> SaveAsync()
    {
        if (!HasPendingChanges || IsSaving)
            return false;

        // Check every value here first, with the same rules the writer applies.
        foreach (var (name, value) in _pending)
        {
            var definition = SettingsCatalog.Definitions.First(d => d.Name == name);
            if (SettingsApply.Validate(definition, value).Error is { } error)
                return Fail(error);
        }

        var changes = new Dictionary<string, string?>(_pending, StringComparer.OrdinalIgnoreCase);
        IsSaving = true;
        try
        {
            if (IsElevated)
            {
                var result = await Task.Run(() => SettingsApply.Apply(changes));
                if (!result.Succeeded)
                    return Fail(string.Join("; ", result.Errors));
            }
            else
            {
                var exitCode = await RunElevatedApplyAsync(changes);
                if (exitCode is null)
                    return Fail("administrator approval was declined.");
                if (exitCode != SettingsApply.ExitSaved)
                    return Fail(SettingsApply.ExitReason(exitCode.Value));
            }
        }
        catch (Exception ex)
        {
            return Fail(ex.Message);
        }
        finally
        {
            IsSaving = false;
        }

        SaveFailed = false;
        SaveMessage = changes.Count == 1
            ? SavedMessage(changes.Keys.Single(), changes.Values.Single())
            : $"Saved {changes.Count} settings";
        _pending.Clear();
        OnPropertyChanged(nameof(HasPendingChanges));
        Load();
        return true;
    }

    private static string SavedMessage(string name, string? value)
    {
        var definition = SettingsCatalog.Definitions.First(d => d.Name == name);
        return definition.Kind != SettingKind.Secret && string.IsNullOrWhiteSpace(value)
            ? $"Cleared {definition.Label}"
            : $"Saved {definition.Label}";
    }

    private bool Fail(string reason)
    {
        SaveFailed = true;
        SaveMessage = $"Not saved: {reason}";
        return false;
    }

    /// <summary>
    /// Starts this app elevated in its apply mode and hands it the changes over a named
    /// pipe only this user, Administrators and SYSTEM can open; nothing is written to disk.
    /// Returns its exit code, or null when the UAC prompt was declined.
    /// </summary>
    private static async Task<int?> RunElevatedApplyAsync(IReadOnlyDictionary<string, string?> changes)
    {
        var exe = Environment.ProcessPath
            ?? throw new InvalidOperationException("could not find the app's own executable.");
        var pipeName = SettingsApply.NewPipeName();
        using var pipe = SettingsApply.CreatePipe(pipeName);

        Process process;
        try
        {
            process = Process.Start(PrefsElevation.BuildApplySettings(exe, pipeName))
                ?? throw new InvalidOperationException("the administrator copy did not start.");
        }
        catch (Exception ex) when (PrefsElevation.IsElevationCancelled(ex))
        {
            return null;
        }

        using (process)
        {
            // Stop waiting at the timeout, or as soon as the copy exits without connecting.
            using var timeout = new CancellationTokenSource(SettingsApply.ConnectTimeout);
            _ = process.WaitForExitAsync().ContinueWith(_ =>
            {
                try { timeout.Cancel(); } catch (ObjectDisposedException) { }
            }, TaskScheduler.Default);
            try
            {
                await SettingsApply.SendAsync(pipe, changes, timeout.Token);
            }
            catch (OperationCanceledException) when (!process.HasExited)
            {
                throw new InvalidOperationException("the administrator copy did not connect in time.");
            }
            await process.WaitForExitAsync();
            return process.ExitCode;
        }
    }
}

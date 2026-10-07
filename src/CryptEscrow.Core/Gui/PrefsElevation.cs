using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace CryptEscrow.Gui;

/// <summary>
/// Settings live in HKLM, so the app's Prefs tab is read-only until the app runs
/// elevated. Unlock relaunches it through UAC, opening on Prefs.
/// </summary>
[SupportedOSPlatform("windows")]
public static class PrefsElevation
{
    public const string PrefsArgument = "--prefs";

    /// <summary>ERROR_CANCELLED: the user dismissed the UAC prompt.</summary>
    private const int ErrorCancelled = 1223;

    public static bool IsProcessElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>A field can be edited when the app is elevated and policy does not set it.</summary>
    public static bool CanEdit(bool isElevated, bool isManaged) => isElevated && !isManaged;

    public static ProcessStartInfo BuildElevatedRelaunch(string exePath) => new(exePath)
    {
        UseShellExecute = true,
        Verb = "runas",
        ArgumentList = { PrefsArgument }
    };

    public static bool OpensOnPrefs(IEnumerable<string> args) =>
        args.Any(a => string.Equals(a, PrefsArgument, StringComparison.OrdinalIgnoreCase));

    public static bool IsElevationCancelled(Exception ex) =>
        ex is Win32Exception { NativeErrorCode: ErrorCancelled };
}

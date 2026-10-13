using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace CryptEscrow.Gui;

/// <summary>
/// Settings live in HKLM. The Prefs tab edits them in the normal app and asks for
/// administrator approval only when Save writes them: an unelevated app relaunches its own
/// executable elevated in a windowless mode that reads the pending values from a named pipe,
/// applies them and exits.
/// </summary>
[SupportedOSPlatform("windows")]
public static class PrefsElevation
{
    public const string ApplySettingsArgument = "--apply-settings";

    /// <summary>ERROR_CANCELLED: the user dismissed the UAC prompt.</summary>
    private const int ErrorCancelled = 1223;

    public static bool IsProcessElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>A field can be edited unless policy sets it.</summary>
    public static bool CanEdit(bool isManaged) => !isManaged;

    /// <summary>The elevated, windowless relaunch that reads the changes from <paramref name="pipeName"/>.</summary>
    public static ProcessStartInfo BuildApplySettings(string exePath, string pipeName) => new(exePath)
    {
        UseShellExecute = true,
        Verb = "runas",
        ArgumentList = { ApplySettingsArgument, pipeName }
    };

    /// <summary>The pipe name when the app was started in its windowless apply mode.</summary>
    public static string? ApplySettingsPipe(IReadOnlyList<string> args)
    {
        for (var i = 0; i < args.Count - 1; i++)
        {
            if (string.Equals(args[i], ApplySettingsArgument, StringComparison.OrdinalIgnoreCase))
                return args[i + 1];
        }
        return null;
    }

    public static bool IsElevationCancelled(Exception ex) =>
        ex is Win32Exception { NativeErrorCode: ErrorCancelled };
}

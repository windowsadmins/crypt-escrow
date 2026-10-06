using System.Text.RegularExpressions;

namespace CryptEscrow.Gui;

/// <summary>
/// Removes BitLocker recovery passwords from text before it is shown or logged. A
/// recovery password is eight groups of six digits separated by hyphens. Nothing this
/// tool writes should contain one, so this is a backstop, not the only guard.
/// </summary>
public static partial class RecoveryKeyRedactor
{
    public const string Replacement = "[recovery key redacted]";

    [GeneratedRegex(@"(?<!\d)\d{6}(?:[-\s]?\d{6}){7}(?!\d)")]
    private static partial Regex RecoveryPassword();

    public static string Redact(string text) =>
        string.IsNullOrEmpty(text) ? text : RecoveryPassword().Replace(text, Replacement);
}

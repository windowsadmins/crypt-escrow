using System.Globalization;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using CryptEscrow.Services;

namespace CryptEscrow.Gui;

/// <summary>
/// Writes the Prefs tab's pending changes to the machine settings key. The app calls it
/// directly when it is elevated, and otherwise hands the changes to an elevated copy of
/// itself over a named pipe (<see cref="PrefsElevation.ApplySettingsArgument"/>), so the
/// values, secrets included, never touch disk. Either way
/// policy is read again here and every policy-managed setting is skipped, and each value is
/// checked with the same rules the tab uses.
/// </summary>
[SupportedOSPlatform("windows")]
public static class SettingsApply
{
    /// <summary>The outcome of one apply: what was written and what was not, and why.</summary>
    public sealed record Result(IReadOnlyList<string> Saved, IReadOnlyList<string> SkippedManaged, IReadOnlyList<string> Errors)
    {
        public bool Succeeded => Errors.Count == 0;
    }

    /// <summary>
    /// Checks a value against its setting's kind. Returns the value to save (trimmed, a
    /// choice in its listed spelling, null to clear), or an error message.
    /// </summary>
    public static (string? Value, string? Error) Validate(SettingDefinition definition, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return (null, null);

        value = definition.Kind == SettingKind.Secret ? value : value.Trim();
        switch (definition.Kind)
        {
            case SettingKind.Toggle:
                return ConfigService.ParseBool(value) is { } b
                    ? (b ? "true" : "false", null)
                    : (null, $"{definition.Label} must be on or off");
            case SettingKind.Number:
                return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) && n >= 0
                    ? (n.ToString(CultureInfo.InvariantCulture), null)
                    : (null, $"{definition.Label} must be a whole number of 0 or more");
            case SettingKind.Choice:
                var choice = definition.Choices?.FirstOrDefault(c => string.Equals(c, value, StringComparison.OrdinalIgnoreCase));
                return choice is not null ? (choice, null) : (null, $"{definition.Label} must be one of {string.Join(", ", definition.Choices ?? [])}");
            default:
                return (value, null);
        }
    }

    /// <summary>Writes each change; a null value clears the saved value.</summary>
    public static Result Apply(IReadOnlyDictionary<string, string?> changes)
    {
        var saved = new List<string>();
        var skipped = new List<string>();
        var errors = new List<string>();

        foreach (var (name, raw) in changes)
        {
            var definition = SettingsCatalog.Definitions.FirstOrDefault(d => string.Equals(d.Name, name, StringComparison.OrdinalIgnoreCase));
            if (definition is null)
            {
                errors.Add($"{name} is not a setting");
                continue;
            }
            if (IsManaged(definition.Name))
            {
                skipped.Add(definition.Name);
                continue;
            }
            var (value, error) = Validate(definition, raw);
            if (error is not null)
            {
                errors.Add(error);
                continue;
            }
            try
            {
                SettingsCatalog.Save(definition.Name, value);
                saved.Add(definition.Name);
            }
            catch (Exception ex)
            {
                errors.Add($"{definition.Label}: {ex.Message}");
            }
        }
        return new Result(saved, skipped, errors);
    }

    private static bool IsManaged(string name) =>
        ConfigService.GetPolicyValue(name) is not null
        || (SecretStore.IsSecret(name) && SecretStore.IsSetByPolicy(name));

    // ── Payload ─────────────────────────────────────────────────

    /// <summary>Exit codes of the windowless apply mode.</summary>
    public const int ExitSaved = 0;
    public const int ExitInvalid = 1;
    public const int ExitUnreadable = 2;
    public const int ExitWriteFailed = 3;

    public static string Serialize(IReadOnlyDictionary<string, string?> changes)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            foreach (var (name, value) in changes)
            {
                if (value is null)
                    writer.WriteNull(name);
                else
                    writer.WriteString(name, value);
            }
            writer.WriteEndObject();
        }
        return System.Text.Encoding.UTF8.GetString(stream.ToArray());
    }

    public static Dictionary<string, string?> Deserialize(string json)
    {
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            throw new JsonException("The settings payload is not an object");
        var changes = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var property in document.RootElement.EnumerateObject())
        {
            changes[property.Name] = property.Value.ValueKind switch
            {
                JsonValueKind.Null => null,
                JsonValueKind.String => property.Value.GetString(),
                _ => throw new JsonException($"{property.Name} is not a string")
            };
        }
        return changes;
    }

    // ── Pipe ────────────────────────────────────────────────────

    private const string PipePrefix = "crypt-escrow-settings-";

    /// <summary>How long the app waits for the elevated copy to connect, UAC prompt included.</summary>
    public static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(60);

    public static string NewPipeName() => PipePrefix + Guid.NewGuid().ToString("N");

    /// <summary>Only a pipe name this app makes is accepted by the apply mode.</summary>
    public static bool IsPipeName(string name) =>
        name.StartsWith(PipePrefix, StringComparison.Ordinal)
        && Guid.TryParseExact(name[PipePrefix.Length..], "N", out _);

    /// <summary>
    /// The app's end of the pipe: one instance, created first so no one else can own the
    /// name, open only to the current user, Administrators and SYSTEM. Administrators covers
    /// an elevated copy running as a different administrator (over-the-shoulder UAC).
    /// </summary>
    public static NamedPipeServerStream CreatePipe(string name)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var security = new PipeSecurity();
        foreach (var sid in PipeAllowedSids(identity.User!))
            security.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.ReadWrite, AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(name, PipeDirection.Out, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 0, 0, security);
    }

    internal static IReadOnlyList<SecurityIdentifier> PipeAllowedSids(SecurityIdentifier user) =>
    [
        user,
        new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
        new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)
    ];

    /// <summary>Waits for the elevated copy, sends the changes and closes the pipe.</summary>
    public static async Task SendAsync(NamedPipeServerStream pipe, IReadOnlyDictionary<string, string?> changes, CancellationToken cancel)
    {
        await pipe.WaitForConnectionAsync(cancel);
        var bytes = Encoding.UTF8.GetBytes(Serialize(changes));
        await pipe.WriteAsync(bytes, cancel);
        await pipe.FlushAsync(cancel);
        pipe.WaitForPipeDrain();
        pipe.Disconnect();
    }

    /// <summary>
    /// The windowless apply mode: reads the changes from the app's pipe, writes them and
    /// returns an exit code. It writes nothing but the settings, and reports only through
    /// its exit code.
    /// </summary>
    public static int RunFromPipe(string pipeName)
    {
        if (!IsPipeName(pipeName))
            return ExitUnreadable;
        string json;
        try
        {
            using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.In);
            pipe.Connect((int)TimeSpan.FromSeconds(10).TotalMilliseconds);
            using var reader = new StreamReader(pipe, Encoding.UTF8);
            json = reader.ReadToEnd();
        }
        catch (Exception)
        {
            return ExitUnreadable;
        }
        return RunFromJson(json);
    }

    /// <summary>Applies a serialized set of changes, all or nothing on validation.</summary>
    public static int RunFromJson(string json)
    {
        Dictionary<string, string?> changes;
        try
        {
            changes = Deserialize(json);
        }
        catch (Exception)
        {
            return ExitUnreadable;
        }

        // Nothing is written unless every value is valid.
        if (changes.Any(c => SettingsCatalog.Definitions.FirstOrDefault(d =>
                string.Equals(d.Name, c.Key, StringComparison.OrdinalIgnoreCase)) is not { } definition
            || Validate(definition, c.Value).Error is not null))
            return ExitInvalid;

        return Apply(changes).Succeeded ? ExitSaved : ExitWriteFailed;
    }

    /// <summary>The reason shown under Save for an apply-mode exit code.</summary>
    public static string ExitReason(int exitCode) => exitCode switch
    {
        ExitSaved => "",
        ExitInvalid => "a value was not valid",
        ExitUnreadable => "the changes could not be handed to the administrator copy",
        ExitWriteFailed => "the machine settings could not be written",
        _ => $"the administrator copy exited with code {exitCode}"
    };
}

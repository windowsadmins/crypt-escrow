using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using CryptEscrow.Services;

namespace CryptEscrow.Gui;

/// <summary>
/// Writes the Prefs tab's pending changes to the machine settings key. The app calls it
/// directly when it is elevated, and otherwise hands the changes to an elevated copy of
/// itself as a JSON file (<see cref="PrefsElevation.ApplySettingsArgument"/>). Either way
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

    /// <summary>Writes the changes to a new file in the user's temp folder.</summary>
    public static string WritePayload(IReadOnlyDictionary<string, string?> changes)
    {
        var path = Path.Combine(Path.GetTempPath(), $"crypt-escrow-settings-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, Serialize(changes));
        return path;
    }

    /// <summary>
    /// The windowless apply mode: reads the payload, writes it and returns an exit code.
    /// It writes nothing but the settings: the payload sits in a folder the user controls,
    /// so the elevated copy reports only through its exit code.
    /// </summary>
    public static int RunFromFile(string payloadPath)
    {
        Dictionary<string, string?> changes;
        try
        {
            changes = Deserialize(File.ReadAllText(payloadPath));
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

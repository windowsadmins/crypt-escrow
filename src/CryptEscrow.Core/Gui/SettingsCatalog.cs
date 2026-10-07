using System.Runtime.Versioning;
using CryptEscrow.Services;

namespace CryptEscrow.Gui;

public enum SettingKind { Text, Toggle, Number, Choice, Secret }

/// <summary>One setting as the Prefs tab presents it.</summary>
public sealed record SettingDefinition(
    string Name,
    string Label,
    string Group,
    SettingKind Kind,
    string? Placeholder = null,
    IReadOnlyList<string>? Choices = null,
    string? Note = null);

/// <summary>A setting's value in each layer the Prefs tab cares about.</summary>
public sealed record SettingState(
    SettingDefinition Definition,
    string? PolicyValue,
    string? MachineValue,
    string EffectiveValue,
    SettingSource EffectiveSource)
{
    /// <summary>Set by policy: the field shows the policy value and is locked.</summary>
    public bool IsManaged => PolicyValue is not null;

    /// <summary>
    /// What the field holds: the policy value when managed, otherwise the machine
    /// setting. Never the secret itself.
    /// </summary>
    public string? FieldValue => Definition.Kind == SettingKind.Secret
        ? null
        : IsManaged ? PolicyValue : MachineValue;

    /// <summary>A toggle shows the effective value when nothing is saved at this layer.</summary>
    public bool ToggleValue => ConfigService.ParseBool(FieldValue) ?? ConfigService.ParseBool(EffectiveValue) ?? false;

    /// <summary>
    /// For a secret, whether one is saved, and only once the app is elevated. The value
    /// itself is never read into the app's view.
    /// </summary>
    public string SecretStatus(bool isElevated)
    {
        if (!isElevated)
            return "Unlock to see whether this is saved";
        if (PolicyValue is not null)
            return MachineValue is not null ? "Saved (by policy)" : "Not saved (managed by policy)";
        return MachineValue is not null ? "Saved" : "Not saved";
    }

    /// <summary>Caption under an unmanaged field: what applies when the field is empty.</summary>
    public string SourceCaption => EffectiveSource switch
    {
        SettingSource.Policy => "Managed by policy",
        SettingSource.MachineSettings => "Saved on this device",
        SettingSource.Environment => $"From the environment: {EffectiveValue}",
        SettingSource.LegacyFile => $"From config.yaml: {EffectiveValue}",
        SettingSource.Default => $"Default: {EffectiveValue}",
        _ => ""
    };
}

/// <summary>The settings the Prefs tab shows, grouped into its cards.</summary>
[SupportedOSPlatform("windows")]
public static class SettingsCatalog
{
    public const string Connection = "Connection";
    public const string Escrow = "Escrow";
    public const string Authentication = "Authentication";
    public const string Logging = "Logging";

    public static IReadOnlyList<string> Groups { get; } = [Connection, Escrow, Authentication, Logging];

    public static IReadOnlyList<SettingDefinition> Definitions { get; } =
    [
        new("ServerUrl", "Server URL", Connection, SettingKind.Text, "https://crypt.example.com"),
        new("SkipCertCheck", "Skip TLS certificate checks", Connection, SettingKind.Toggle),

        new("AutoRotate", "Rotate the key when the server asks", Escrow, SettingKind.Toggle),
        new("CleanupOldProtectors", "Remove old recovery keys after rotation", Escrow, SettingKind.Toggle),
        new("ValidateKey", "Validate the key locally before escrow", Escrow, SettingKind.Toggle),
        new("KeyEscrowIntervalHours", "Escrow interval (hours)", Escrow, SettingKind.Number),
        new("SkipUsers", "Users to skip", Escrow, SettingKind.Text, "comma-separated"),
        new("PostRunCommand", "Command to run after an error", Escrow, SettingKind.Text),

        new("ApiKey", "API key", Authentication, SettingKind.Secret),
        new("ApiKeyHeader", "API key header", Authentication, SettingKind.Text, "X-API-Key"),
        new("UseMtls", "Use a client certificate (mTLS)", Authentication, SettingKind.Toggle),
        new("CertificateSubject", "Certificate subject", Authentication, SettingKind.Text),
        new("CertificateThumbprint", "Certificate thumbprint", Authentication, SettingKind.Text),
        new("CertificateStoreLocation", "Certificate store location", Authentication, SettingKind.Choice,
            Choices: ["LocalMachine", "CurrentUser"]),
        new("CertificateStoreName", "Certificate store name", Authentication, SettingKind.Text, "My"),
        new("PfxPath", "PFX file", Authentication, SettingKind.Text, @"C:\ProgramData\ManagedEncryption\client.pfx"),
        new("PfxPasswordCredential", "PFX passphrase credential name", Authentication, SettingKind.Text,
            Note: "The passphrase itself stays in Windows Credential Manager under this name, in the account that runs the escrow. The app does not read it."),
        new("ClientCertPath", "PEM certificate file", Authentication, SettingKind.Text),
        new("ClientKeyPath", "PEM key file", Authentication, SettingKind.Text),

        new("LogLevel", "Log level", Logging, SettingKind.Choice, Choices: ["DEBUG", "INFO", "WARN", "ERROR"]),
        new("LogFilePath", "Log file", Logging, SettingKind.Text),
        new("LogRetainedDays", "Days of logs to keep", Logging, SettingKind.Number),
    ];

    /// <summary>Stands in for a saved secret's value, which is never loaded.</summary>
    internal const string SavedMarker = "(saved)";

    /// <summary>Reads every setting's policy, machine and effective values.</summary>
    public static IReadOnlyList<SettingState> Load()
    {
        var effective = ConfigService.Describe().ToDictionary(d => d.Name, StringComparer.OrdinalIgnoreCase);
        return Definitions.Select(definition =>
        {
            var (_, value, source) = effective[definition.Name];
            if (definition.Kind == SettingKind.Secret)
            {
                // Only whether a secret exists is ever loaded, never its value. Policy that
                // names it still manages it after the CLI has moved it and blanked the copy.
                var managed = SecretStore.IsSetByPolicy(definition.Name);
                var saved = SecretStore.Read(definition.Name) is not null
                    || ConfigService.GetPolicyValue(definition.Name) is not null
                    || ConfigService.GetSettingsValue(definition.Name) is not null;
                return new SettingState(definition, managed ? string.Empty : null,
                    saved ? SavedMarker : null, value, source);
            }
            return new SettingState(
                definition,
                ConfigService.GetPolicyValue(definition.Name),
                ConfigService.GetSettingsValue(definition.Name),
                value,
                source);
        }).ToList();
    }

    /// <summary>
    /// Saves one field to the machine settings key; an empty value removes it so the
    /// layers below apply again. Refuses a setting policy manages.
    /// </summary>
    public static void Save(string name, string? value)
    {
        if (ConfigService.GetPolicyValue(name) is not null
            || (SecretStore.IsSecret(name) && SecretStore.IsSetByPolicy(name)))
            throw new InvalidOperationException($"{name} is managed by policy");

        if (string.IsNullOrWhiteSpace(value))
            ConfigService.ClearValue(name);
        else
            ConfigService.SetValue(name, value.Trim());
    }
}

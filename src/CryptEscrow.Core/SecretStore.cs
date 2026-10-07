using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace CryptEscrow.Services;

/// <summary>
/// Where credentials live: <c>HKLM\SOFTWARE\Crypt\ManagedEncryption\Secrets</c>, with its
/// own ACL (SYSTEM and Administrators full control, nobody else). The policy key, the
/// settings key, machine environment variables and config.yaml are readable by every
/// user, so a credential found in any of them is moved here and the readable copy removed.
/// </summary>
/// <remarks>
/// Only an elevated process can read or write the store; a standard user's process reads
/// nothing and treats the secret as unset. Values are never logged. Beside each secret the
/// store keeps the layer it came from, so a lower layer never replaces a value that policy
/// supplied.
/// </remarks>
[SupportedOSPlatform("windows")]
public static partial class SecretStore
{
    public const string RegistryPath = @"SOFTWARE\Crypt\ManagedEncryption\Secrets";
    private const string SourceSuffix = ".Source";

    /// <summary>The settings that hold credentials, with their environment variables.</summary>
    public static readonly IReadOnlyDictionary<string, string> Secrets =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["ApiKey"] = "CRYPT_API_KEY",
        };

    public static bool IsSecret(string name) => Secrets.ContainsKey(name);

    // ── Locations (test seams) ──────────────────────────────────

    /// <summary>The keys the store and the readable layers live in.</summary>
    internal sealed record Locations(
        RegistryKey Root,
        string SecretsPath,
        IReadOnlyList<string> PolicyPaths,
        string SettingsPath,
        bool ApplyAcl);

    /// <summary>Tests point this at an HKCU subtree; production leaves it null.</summary>
    internal static Locations? LocationsOverride { get; set; }

    /// <summary>Tests replace machine environment access; production leaves these null.</summary>
    internal static Func<string, string?>? MachineEnvironmentReader { get; set; }
    internal static Action<string>? MachineEnvironmentClearer { get; set; }

    private static readonly Lazy<RegistryKey> Hklm64 =
        new(() => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64));

    private static Locations Current => LocationsOverride ?? new Locations(
        Hklm64.Value,
        RegistryPath,
        [ConfigService.PolicyKeyPath, ConfigService.PolicyKeyPathMdm],
        ConfigService.SettingsKeyPath,
        ApplyAcl: true);

    // ── Read / Write ────────────────────────────────────────────

    /// <summary>The stored value, or null when unset or this process may not read it.</summary>
    public static string? Read(string name)
    {
        try
        {
            using var key = Current.Root.OpenSubKey(Current.SecretsPath);
            return key?.GetValue(name) is string s && s.Length > 0 ? s : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>The layer the stored value came from, or null when nothing is stored.</summary>
    public static SettingSource? ReadSource(string name)
    {
        try
        {
            using var key = Current.Root.OpenSubKey(Current.SecretsPath);
            return key?.GetValue(name + SourceSuffix) is string s && Enum.TryParse<SettingSource>(s, out var source)
                ? source
                : Read(name) is null ? null : SettingSource.MachineSettings;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Stores <paramref name="value"/> as coming from <paramref name="source"/>, or removes
    /// the entry when it is empty, and reads it back. Throws when the store's ACL cannot be
    /// set or the value does not read back, so a caller never removes a readable copy the
    /// store does not hold. Must run elevated.
    /// </summary>
    public static void Write(string name, string? value, SettingSource source = SettingSource.MachineSettings)
    {
        using (var key = OpenProtected())
        {
            if (string.IsNullOrEmpty(value))
            {
                key.DeleteValue(name, throwOnMissingValue: false);
                key.DeleteValue(name + SourceSuffix, throwOnMissingValue: false);
            }
            else
            {
                key.SetValue(name, value, RegistryValueKind.String);
                key.SetValue(name + SourceSuffix, source.ToString(), RegistryValueKind.String);
            }
        }

        if (!string.Equals(Read(name), string.IsNullOrEmpty(value) ? null : value, StringComparison.Ordinal))
            throw new InvalidOperationException($"{name} did not read back from the protected store");
    }

    // ── Migration ───────────────────────────────────────────────

    /// <summary>
    /// Moves every secret found in a user-readable place into the store, lowest precedence
    /// first: config.yaml, the machine environment, the settings key, then policy. A layer
    /// below the one the store's value came from does not replace it. Each readable copy is
    /// removed only after the store holds the value; a policy copy is blanked rather than
    /// deleted, so the setting still shows as managed. Returns one line per move or failure,
    /// naming the setting and place, never the value. Must run elevated.
    /// </summary>
    public static List<string> MigrateReadableCopies()
    {
        var notes = new List<string>();
        var locations = Current;

        foreach (var (name, envVar) in Secrets)
        {
            try
            {
                MigrateFromFile(name, notes);
                Migrate(name, SettingSource.Environment, $"machine environment variable {envVar}",
                    () => ReadMachineEnvironment(envVar),
                    () => ClearMachineEnvironment(envVar), notes);
                Migrate(name, SettingSource.MachineSettings, $"HKLM\\{locations.SettingsPath}",
                    () => ReadString(locations.SettingsPath, name),
                    () => { using var k = locations.Root.OpenSubKey(locations.SettingsPath, writable: true); k?.DeleteValue(name, false); },
                    notes);
                foreach (var policyPath in locations.PolicyPaths)
                {
                    Migrate(name, SettingSource.Policy, $"HKLM\\{policyPath}",
                        () => ReadString(policyPath, name),
                        () => { using var k = locations.Root.OpenSubKey(policyPath, writable: true); k?.SetValue(name, string.Empty, RegistryValueKind.String); },
                        notes);
                }
            }
            catch (Exception ex)
            {
                notes.Add($"Could not move {name} to the protected store: {ex.Message}");
            }
        }

        return notes;
    }

    /// <summary>True when policy names the setting at all, even with the blanked copy.</summary>
    public static bool IsSetByPolicy(string name)
    {
        try
        {
            foreach (var path in Current.PolicyPaths)
            {
                using var key = Current.Root.OpenSubKey(path);
                if (key?.GetValue(name) is not null)
                    return true;
            }
        }
        catch
        {
            // Unreadable policy is treated as absent, as everywhere else.
        }
        return false;
    }

    private static void Migrate(string name, SettingSource source, string place,
        Func<string?> read, Action remove, List<string> notes)
    {
        var value = read();
        if (string.IsNullOrEmpty(value))
            return;

        var stored = Read(name) is null ? null : ReadSource(name);
        if (stored is null || source >= stored)
            Write(name, value, source);

        // The store now holds this value or one from a higher layer: the copy can go.
        if (Read(name) is null)
            throw new InvalidOperationException($"{name} is not in the protected store; left in {place}");

        remove();
        notes.Add(stored is not null && source < stored
            ? $"Removed {name} from {place}: the protected store already holds a value from {stored}"
            : $"Moved {name} from {place} to the protected store");
    }

    [GeneratedRegex(@"^[ \t]*api_key[ \t]*:.*(?:\r?\n)?", RegexOptions.Multiline)]
    private static partial Regex ApiKeyLine();

    private static void MigrateFromFile(string name, List<string> notes)
    {
        if (!string.Equals(name, "ApiKey", StringComparison.OrdinalIgnoreCase))
            return;

        // LoadConfig returns null for an untrusted file, which is never imported.
        var value = ConfigService.LoadConfig()?.Server?.Auth?.ApiKey;
        if (string.IsNullOrEmpty(value))
            return;

        var path = ConfigService.GetConfigPath();
        Migrate(name, SettingSource.LegacyFile, path, () => value, () =>
        {
            var yaml = File.ReadAllText(path);
            File.WriteAllText(path, ApiKeyLine().Replace(yaml, string.Empty));
        }, notes);
    }

    private static string? ReadString(string path, string name)
    {
        using var key = Current.Root.OpenSubKey(path);
        return key?.GetValue(name) as string;
    }

    private static string? ReadMachineEnvironment(string name) =>
        MachineEnvironmentReader is { } reader
            ? reader(name)
            : Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Machine);

    private static void ClearMachineEnvironment(string name)
    {
        if (MachineEnvironmentClearer is { } clearer)
            clearer(name);
        else
            Environment.SetEnvironmentVariable(name, null, EnvironmentVariableTarget.Machine);
    }

    // ── ACL ─────────────────────────────────────────────────────

    /// <summary>SYSTEM and Administrators full control, nothing else, not inherited.</summary>
    internal static RegistrySecurity ProtectedSecurity()
    {
        var security = new RegistrySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
        {
            security.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(sid, null),
                RegistryRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
        }
        return security;
    }

    /// <summary>Null when only SYSTEM and Administrators can read the key; otherwise why not.</summary>
    internal static string? WhyUnprotected(RegistrySecurity security)
    {
        if (!security.AreAccessRulesProtected)
            return "it inherits permissions from its parent";

        foreach (RegistryAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow)
                continue;
            var sid = rule.IdentityReference as SecurityIdentifier;
            if (!TrustedFile.IsTrustedAccount(sid))
                return $"{sid?.Value ?? rule.IdentityReference.Value} has access";
        }
        return null;
    }

    /// <summary>
    /// Opens the store for writing, creating it, and resets its ACL every time. Throws when
    /// the ACL does not hold afterwards, so nothing is written to a readable key.
    /// </summary>
    private static RegistryKey OpenProtected()
    {
        var locations = Current;
        var key = locations.Root.CreateSubKey(locations.SecretsPath, writable: true);
        if (!locations.ApplyAcl)
            return key;

        try
        {
            key.SetAccessControl(ProtectedSecurity());
            if (WhyUnprotected(key.GetAccessControl()) is { } reason)
                throw new InvalidOperationException($"the protected store is not protected: {reason}");
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }
}

using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace CryptEscrow.Services;

/// <summary>
/// Keeps ProgramData\ManagedEncryption for administrators on every SYSTEM run, so an
/// install that predates the installer's ACL is fixed without a reinstall.
/// </summary>
/// <remarks>
/// <para>Resets the folder to SYSTEM and Administrators full control and Users read, not
/// inherited from ProgramData. Below it, links are removed, never followed. Every other
/// entry owned by an individual account has its owner normalised to Administrators and
/// its own entries dropped, so it inherits the folder's ACL.</para>
/// <para>The exception is the first lockdown of a folder that was open to every user: an
/// entry from that time whose owner cannot be resolved as an administrator may have come
/// from a standard user, so it is moved to <c>quarantine\&lt;timestamp&gt;</c> and logged,
/// never deleted. Once the folder is locked, only an administrator can create anything in
/// it, so later entries are normalised instead.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
internal static class DataDirectoryGuard
{
    public const string QuarantineFolder = "quarantine";

    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);

    internal enum Action { Keep, Normalise, Quarantine, RemoveLink }

    internal static bool IsRunningAsSystem()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User == System;
    }

    /// <summary>What to do with one entry below the folder.</summary>
    /// <param name="folderWasLocked">The folder was already locked before this run.</param>
    /// <param name="ownerIsKnownAdministrator">The owner resolves as a local administrator.</param>
    internal static Action Decide(bool isLink, SecurityIdentifier? owner, bool underLogs,
        bool folderWasLocked, bool ownerIsKnownAdministrator)
    {
        if (isLink)
            return Action.RemoveLink;
        if (TrustedFile.IsTrustedAccount(owner))
            return Action.Keep;
        // Logs are only read by people, never acted on; a locked folder admits only
        // administrators; a resolvable administrator is one. All three are kept.
        if (underLogs || folderWasLocked || ownerIsKnownAdministrator)
            return Action.Normalise;
        return Action.Quarantine;
    }

    /// <summary>
    /// Whether <paramref name="security"/> already holds the folder for administrators: no
    /// one else may create, delete or re-permission anything, and nothing is inherited.
    /// </summary>
    internal static bool IsLocked(string root, DirectorySecurity security) =>
        security.AreAccessRulesProtected && TrustedFile.Evaluate(root, security) is null;

    /// <summary>
    /// Locks <paramref name="root"/> down and returns one line per thing it changed or
    /// could not fix, for the caller to log once its log is open.
    /// </summary>
    /// <param name="lockAcl">Tests pass false to run the sweep without changing any ACL or owner.</param>
    /// <param name="ownerOf">Test seam for the owner lookup.</param>
    /// <param name="folderWasLocked">Test seam: whether the folder counts as already locked.</param>
    internal static List<string> Secure(string root, bool lockAcl = true,
        Func<FileSystemInfo, SecurityIdentifier?>? ownerOf = null, bool? folderWasLocked = null,
        DateTime? now = null)
    {
        var notes = new List<string>();
        ownerOf ??= OwnerOf;

        try
        {
            var info = new DirectoryInfo(root);
            if (info.Exists && info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                // Non-recursive: removes the link itself, not what it points at.
                Directory.Delete(root);
                notes.Add($"Removed {root}: it was a link, not a folder");
            }

            Directory.CreateDirectory(root);
            var folder = new DirectoryInfo(root);
            var current = folder.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            var wasLocked = folderWasLocked ?? IsLocked(root, current);

            if (lockAcl && !wasLocked)
            {
                folder.SetAccessControl(LockedSecurity());
                notes.Add($"Locked {root} to SYSTEM and Administrators (Users read)");
            }

            var quarantine = Path.Combine(root, QuarantineFolder, (now ?? DateTime.Now).ToString("yyyyMMdd-HHmmss"));
            Sweep(folder, root, quarantine, wasLocked, lockAcl, ownerOf, notes);
        }
        catch (Exception ex)
        {
            notes.Add($"Could not secure {root}: {ex.Message}");
        }

        return notes;
    }

    /// <summary>The installer's ACL: SYSTEM and Administrators full control, Users read, protected.</summary>
    private static DirectorySecurity LockedSecurity()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags all = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl, all, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, all, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.ReadAndExecute, all, PropagationFlags.None, AccessControlType.Allow));
        security.SetOwner(Administrators);
        return security;
    }

    private static void Sweep(DirectoryInfo directory, string root, string quarantine, bool wasLocked,
        bool lockAcl, Func<FileSystemInfo, SecurityIdentifier?> ownerOf, List<string> notes)
    {
        List<FileSystemInfo> entries;
        try
        {
            entries = directory.EnumerateFileSystemInfos("*", new EnumerationOptions
            {
                AttributesToSkip = 0,
                IgnoreInaccessible = false,
                RecurseSubdirectories = false
            }).ToList();
        }
        catch (Exception ex)
        {
            notes.Add($"Could not list {directory.FullName}: {ex.Message}");
            return;
        }

        foreach (var entry in entries)
        {
            var relative = Path.GetRelativePath(root, entry.FullName);
            // What is already quarantined is never read; leave it as it is.
            if (relative.Equals(QuarantineFolder, StringComparison.OrdinalIgnoreCase))
                continue;

            try
            {
                var isLink = entry.Attributes.HasFlag(FileAttributes.ReparsePoint);
                var owner = isLink ? null : ownerOf(entry);
                var underLogs = relative.Equals("logs", StringComparison.OrdinalIgnoreCase) ||
                    relative.StartsWith("logs" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

                switch (Decide(isLink, owner, underLogs, wasLocked, AdminMembership.IsKnownAdministrator(owner)))
                {
                    case Action.RemoveLink:
                        // A link is removed on its own, never followed.
                        if (entry is DirectoryInfo) Directory.Delete(entry.FullName);
                        else File.Delete(entry.FullName);
                        notes.Add($"Removed {entry.FullName}: a link");
                        break;

                    case Action.Quarantine:
                        // Links inside are removed first, so nothing moved points elsewhere.
                        if (entry is DirectoryInfo planted) RemoveLinks(planted, notes);
                        var target = Path.Combine(quarantine, relative);
                        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                        if (entry is DirectoryInfo dir) dir.MoveTo(target);
                        else ((FileInfo)entry).MoveTo(target);
                        notes.Add($"Quarantined {entry.FullName} to {target}: it predates the folder's lockdown and its owner ({owner?.Value ?? "unknown"}) is not a known administrator");
                        break;

                    case Action.Normalise:
                        if (lockAcl)
                        {
                            Normalise(entry);
                            notes.Add($"Set the owner of {entry.FullName} to Administrators (was {owner?.Value ?? "unknown"})");
                        }
                        if (entry is DirectoryInfo normalised) Sweep(normalised, root, quarantine, wasLocked, lockAcl, ownerOf, notes);
                        break;

                    default:
                        // An administrator's file stays, but an entry of its own that lets
                        // others write it goes: it inherits the folder's ACL instead.
                        if (lockAcl && entry is FileInfo file &&
                            TrustedFile.Evaluate(file.FullName, file.GetAccessControl(), ownerVouchedByParent: true) is { } reason)
                        {
                            Normalise(file);
                            notes.Add($"Reset permissions on {file.FullName}: {reason}");
                        }
                        if (entry is DirectoryInfo keep) Sweep(keep, root, quarantine, wasLocked, lockAcl, ownerOf, notes);
                        break;
                }
            }
            catch (Exception ex)
            {
                notes.Add($"Could not check {entry.FullName}: {ex.Message}");
            }
        }
    }

    private static void RemoveLinks(DirectoryInfo directory, List<string> notes)
    {
        foreach (var entry in directory.EnumerateFileSystemInfos("*", new EnumerationOptions { AttributesToSkip = 0 }).ToList())
        {
            if (entry.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                if (entry is DirectoryInfo) Directory.Delete(entry.FullName);
                else File.Delete(entry.FullName);
                notes.Add($"Removed {entry.FullName}: a link");
            }
            else if (entry is DirectoryInfo sub)
            {
                RemoveLinks(sub, notes);
            }
        }
    }

    /// <summary>Owner Administrators, explicit entries dropped, the folder's ACL inherited again.</summary>
    private static void Normalise(FileSystemInfo entry)
    {
        if (entry is DirectoryInfo dir)
        {
            var security = new DirectorySecurity();
            security.SetOwner(Administrators);
            security.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
            dir.SetAccessControl(security);
        }
        else if (entry is FileInfo file)
        {
            var security = new FileSecurity();
            security.SetOwner(Administrators);
            security.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
            file.SetAccessControl(security);
        }
    }

    private static SecurityIdentifier? OwnerOf(FileSystemInfo entry)
    {
        try
        {
            return entry switch
            {
                DirectoryInfo d => d.GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier,
                FileInfo f => f.GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier,
                _ => null
            };
        }
        catch
        {
            return null;
        }
    }
}

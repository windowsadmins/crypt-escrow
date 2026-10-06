using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace CryptEscrow.Services;

/// <summary>
/// Keeps ProgramData\ManagedEncryption for administrators on every SYSTEM run, so an
/// install that predates the installer's ACL is fixed without a reinstall.
/// </summary>
/// <remarks>
/// Resets the folder to SYSTEM and Administrators full control and Users read, not
/// inherited from ProgramData, then removes every link and every entry a
/// non-administrator owns. Files SYSTEM or Administrators own, such as a config.yaml a
/// deployment script wrote, are kept and inherit the new ACL. Links are deleted, never
/// followed.
/// </remarks>
[SupportedOSPlatform("windows")]
internal static class DataDirectoryGuard
{
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);

    internal enum Action { Keep, Remove, Reclaim }

    internal static bool IsRunningAsSystem()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User == System;
    }

    /// <summary>What to do with one entry below the folder.</summary>
    internal static Action Decide(bool isLink, SecurityIdentifier? owner, bool underLogs)
    {
        if (isLink)
            return Action.Remove;
        if (TrustedFile.IsTrustedAccount(owner))
            return Action.Keep;
        // Logs are only written, never acted on: keep them, but take them back.
        return underLogs ? Action.Reclaim : Action.Remove;
    }

    /// <summary>
    /// Locks <paramref name="root"/> down and returns one line per thing it changed or
    /// could not fix, for the caller to log once its log is open.
    /// </summary>
    /// <param name="lockAcl">Tests pass false to exercise the sweep without admin.</param>
    /// <param name="ownerOf">Test seam for the owner lookup.</param>
    internal static List<string> Secure(string root, bool lockAcl = true,
        Func<FileSystemInfo, SecurityIdentifier?>? ownerOf = null)
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
            if (lockAcl)
            {
                var current = folder.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
                var reason = TrustedFile.Evaluate(root, current)
                    ?? (current.AreAccessRulesProtected ? null : "it inherited ProgramData's permissions");
                if (reason is not null)
                {
                    folder.SetAccessControl(LockedSecurity());
                    notes.Add($"Reset permissions on {root}: {reason}");
                }
            }
            Sweep(folder, root, lockAcl, ownerOf, notes);
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
        security.SetOwner(System);
        return security;
    }

    private static void Sweep(DirectoryInfo directory, string root, bool lockAcl, Func<FileSystemInfo, SecurityIdentifier?> ownerOf, List<string> notes)
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
            try
            {
                var isLink = entry.Attributes.HasFlag(FileAttributes.ReparsePoint);
                var owner = isLink ? null : ownerOf(entry);
                var relative = Path.GetRelativePath(root, entry.FullName);
                var underLogs = relative.Equals("logs", StringComparison.OrdinalIgnoreCase) ||
                    relative.StartsWith("logs" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

                switch (Decide(isLink, owner, underLogs))
                {
                    case Action.Remove:
                        if (entry is DirectoryInfo dir)
                        {
                            // Empty it first, so links inside are removed rather than followed.
                            if (!isLink) Sweep(dir, root, lockAcl, _ => null, notes);
                            Directory.Delete(dir.FullName, recursive: !isLink);
                        }
                        else
                        {
                            File.Delete(entry.FullName);
                        }
                        notes.Add($"Removed {entry.FullName}: " +
                            (isLink ? "a link" : $"created by a non-administrator ({owner?.Value ?? "unknown owner"})"));
                        break;

                    case Action.Reclaim:
                        Reclaim(entry);
                        notes.Add($"Took ownership of {entry.FullName} (was {owner?.Value ?? "unknown owner"})");
                        if (entry is DirectoryInfo logDir) Sweep(logDir, root, lockAcl, ownerOf, notes);
                        break;

                    default:
                        // An administrator's file stays, but an entry of its own that lets
                        // others write it goes: it inherits the folder's ACL instead.
                        if (lockAcl && entry is FileInfo file &&
                            TrustedFile.Evaluate(file.FullName, file.GetAccessControl()) is { } reason)
                        {
                            Reclaim(file);
                            notes.Add($"Reset permissions on {file.FullName}: {reason}");
                        }
                        if (entry is DirectoryInfo keep) Sweep(keep, root, lockAcl, ownerOf, notes);
                        break;
                }
            }
            catch (Exception ex)
            {
                notes.Add($"Could not check {entry.FullName}: {ex.Message}");
            }
        }
    }

    /// <summary>Owner SYSTEM, explicit entries dropped, the folder's ACL inherited again.</summary>
    private static void Reclaim(FileSystemInfo entry)
    {
        if (entry is DirectoryInfo dir)
        {
            var security = new DirectorySecurity();
            security.SetOwner(System);
            security.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
            dir.SetAccessControl(security);
        }
        else if (entry is FileInfo file)
        {
            var security = new FileSecurity();
            security.SetOwner(System);
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

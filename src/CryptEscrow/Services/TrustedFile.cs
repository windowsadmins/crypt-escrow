using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace CryptEscrow.Services;

/// <summary>
/// Decides whether a file under ProgramData may be trusted by a run as SYSTEM. The
/// escrow task runs as SYSTEM and acts on config.yaml and its own state files, so a
/// file a non-administrator could have written, or could still change, is ignored.
/// </summary>
/// <remarks>
/// A file is trusted when it is not a link, its owner is SYSTEM, Administrators or
/// TrustedInstaller, and neither it nor its folder grants any other account a right
/// that would let it change, replace or re-permission the file. The installer gives
/// ManagedEncryption that ACL: SYSTEM and Administrators full control, Users read,
/// inheritance off.
/// </remarks>
[SupportedOSPlatform("windows")]
internal static class TrustedFile
{
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier TrustedInstaller =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
    private static readonly SecurityIdentifier CreatorOwner = new(WellKnownSidType.CreatorOwnerSid, null);
    private static readonly SecurityIdentifier OwnerRights = new("S-1-3-4");

    private const int GenericAll = 0x10000000;
    private const int GenericWrite = 0x40000000;

    /// <summary>
    /// Rights that let an account change a file, or replace or re-permission the files
    /// in a folder. On a folder WriteData is "create files" and AppendData is "create
    /// folders".
    /// </summary>
    internal const FileSystemRights WriteRights =
        FileSystemRights.WriteData |
        FileSystemRights.AppendData |
        FileSystemRights.Delete |
        FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.ChangePermissions |
        FileSystemRights.TakeOwnership;

    /// <summary>Accounts a SYSTEM run may let own or write its files.</summary>
    internal static bool IsTrustedAccount(SecurityIdentifier? sid) =>
        sid is not null && (sid == System || sid == Administrators || sid == TrustedInstaller);

    /// <summary>
    /// Null when <paramref name="path"/> may be trusted; otherwise why not. Fails closed:
    /// a file whose permissions cannot be read is not trusted.
    /// </summary>
    internal static string? WhyUntrusted(string path)
    {
        try
        {
            var file = new FileInfo(path);
            if (file.Attributes.HasFlag(FileAttributes.ReparsePoint))
                return $"{path} is a link";

            var reason = Evaluate(path,
                file.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access));
            if (reason is not null)
                return reason;

            var folder = file.Directory!;
            if (folder.Attributes.HasFlag(FileAttributes.ReparsePoint))
                return $"{folder.FullName} is a link";

            return Evaluate(folder.FullName,
                folder.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access));
        }
        catch (Exception ex)
        {
            return $"could not read the permissions on {path}: {ex.Message}";
        }
    }

    /// <summary>
    /// Null when the owner is trusted and no other account holds a write right that
    /// applies to the object itself; otherwise why not.
    /// </summary>
    internal static string? Evaluate(string what, FileSystemSecurity security)
    {
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (!IsTrustedAccount(owner))
            return $"{what} is owned by {owner?.Value ?? "an unknown account"}, not by SYSTEM or Administrators";

        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow)
                continue;
            // An inherit-only entry applies to what is created below, not to this object.
            if (rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly))
                continue;

            var sid = rule.IdentityReference as SecurityIdentifier;
            // The owner is already known to be trusted, so its stand-ins are too.
            if (IsTrustedAccount(sid) || sid == CreatorOwner || sid == OwnerRights)
                continue;

            var rights = (int)rule.FileSystemRights;
            if ((rights & ((int)WriteRights | GenericAll | GenericWrite)) != 0)
                return $"{what} can be modified by {sid?.Value ?? rule.IdentityReference.Value}";
        }

        return null;
    }
}

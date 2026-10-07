using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace CryptEscrow.Services;

/// <summary>
/// Whether an account is a direct member of the local Administrators group. Membership
/// through a nested group (an Entra ID role, a domain group) cannot be resolved offline,
/// so such an account reads as not known to be an administrator.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class AdminMembership
{
    /// <summary>Tests replace the lookup; production leaves this null.</summary>
    internal static Func<SecurityIdentifier, bool>? Override { get; set; }

    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    public static bool IsKnownAdministrator(SecurityIdentifier? sid)
    {
        if (sid is null)
            return false;
        if (TrustedFile.IsTrustedAccount(sid))
            return true;
        if (Override is { } lookup)
            return lookup(sid);

        try
        {
            return DirectMembers().Contains(sid);
        }
        catch
        {
            return false;
        }
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(string? server, string group, int level,
        out IntPtr buffer, int maxLength, out int read, out int total, IntPtr resume);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    private static HashSet<SecurityIdentifier> DirectMembers()
    {
        // The group's name is localised; resolve it from its well-known SID.
        var name = ((NTAccount)Administrators.Translate(typeof(NTAccount))).Value;
        name = name[(name.IndexOf('\\') + 1)..];

        var members = new HashSet<SecurityIdentifier>();
        if (NetLocalGroupGetMembers(null, name, 0, out var buffer, -1, out var read, out _, IntPtr.Zero) != 0)
            return members;
        try
        {
            for (var i = 0; i < read; i++)
            {
                var psid = Marshal.ReadIntPtr(buffer, i * IntPtr.Size);
                members.Add(new SecurityIdentifier(psid));
            }
        }
        finally
        {
            NetApiBufferFree(buffer);
        }
        return members;
    }
}

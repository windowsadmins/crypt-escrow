using System.Runtime.InteropServices;

namespace CryptEscrow.Tests.Fixtures;

/// <summary>
/// Test-only helper that writes and deletes Windows Credential Manager entries
/// via advapi32!CredWriteW / CredDeleteW. Uses legacy DllImport (not
/// LibraryImport) because the CREDENTIAL struct contains FILETIME which the
/// LibraryImport source generator refuses to marshal without
/// DisableRuntimeMarshalling — and disabling runtime marshalling project-wide
/// would break other tests. Marshalling overhead is irrelevant in test code.
/// </summary>
internal static class CredentialManagerWriter
{
    private const uint CRED_TYPE_GENERIC = 1;
    private const uint CRED_PERSIST_SESSION = 1;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL
    {
        public uint Flags;
        public uint Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    [DllImport("advapi32.dll", EntryPoint = "CredWriteW", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredWrite(ref CREDENTIAL credential, uint flags);

    [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredDelete(string targetName, uint type, uint reservedFlag);

    public static void WriteGeneric(string targetName, string password)
    {
        var passwordBytes = System.Text.Encoding.Unicode.GetBytes(password);
        var blob = Marshal.AllocHGlobal(passwordBytes.Length);
        var target = Marshal.StringToHGlobalUni(targetName);
        var user = Marshal.StringToHGlobalUni("crypt-escrow-test");
        try
        {
            Marshal.Copy(passwordBytes, 0, blob, passwordBytes.Length);
            var cred = new CREDENTIAL
            {
                Type = CRED_TYPE_GENERIC,
                TargetName = target,
                CredentialBlobSize = (uint)passwordBytes.Length,
                CredentialBlob = blob,
                Persist = CRED_PERSIST_SESSION,
                UserName = user,
            };

            if (!CredWrite(ref cred, 0))
            {
                var err = Marshal.GetLastWin32Error();
                throw new InvalidOperationException($"CredWrite failed for '{targetName}' (Win32 error {err})");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(blob);
            Marshal.FreeHGlobal(target);
            Marshal.FreeHGlobal(user);
        }
    }

    public static void Delete(string targetName)
    {
        CredDelete(targetName, CRED_TYPE_GENERIC, 0);
    }

    /// <summary>
    /// Scoped writer: creates the credential on construction, deletes it on dispose.
    /// </summary>
    public sealed class Scoped : IDisposable
    {
        public string TargetName { get; }

        public Scoped(string targetName, string password)
        {
            TargetName = targetName;
            WriteGeneric(targetName, password);
        }

        public void Dispose() => Delete(TargetName);
    }
}

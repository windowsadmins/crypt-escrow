using System.Runtime.InteropServices;
using Serilog;

namespace CryptEscrow.Services;

/// <summary>
/// Minimal read-only wrapper over Windows Credential Manager (advapi32!CredReadW).
/// Used to retrieve the passphrase for a PFX client certificate without storing
/// it in YAML, environment variables, or the registry.
/// </summary>
internal static partial class CredentialManager
{
    private const uint CRED_TYPE_GENERIC = 1;

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

    [LibraryImport("advapi32.dll", EntryPoint = "CredReadW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CredRead(string target, uint type, uint reservedFlag, out IntPtr credentialPtr);

    [LibraryImport("advapi32.dll", EntryPoint = "CredFree")]
    private static partial void CredFree(IntPtr cred);

    /// <summary>
    /// Reads the password blob of a generic credential by target name.
    /// Returns null if the credential doesn't exist or can't be read.
    /// </summary>
    /// <param name="targetName">
    /// The target name of the Windows Credential Manager entry. Create with
    /// <c>cmdkey /generic:&lt;name&gt; /user:&lt;anything&gt; /pass:&lt;secret&gt;</c>.
    /// </param>
    public static string? ReadGenericPassword(string targetName)
    {
        if (string.IsNullOrWhiteSpace(targetName))
            return null;

        if (!CredRead(targetName, CRED_TYPE_GENERIC, 0, out var ptr))
        {
            var err = Marshal.GetLastWin32Error();
            Log.Warning(
                "Credential Manager: target '{Target}' not found (Win32 error {Err})",
                targetName, err);
            return null;
        }

        try
        {
            var cred = Marshal.PtrToStructure<CREDENTIAL>(ptr);
            if (cred.CredentialBlobSize == 0 || cred.CredentialBlob == IntPtr.Zero)
                return string.Empty;

            // CredentialBlob is raw bytes; cmdkey and PowerShell's Credential
            // Manager APIs store passphrases as UTF-16LE.
            var bytes = new byte[cred.CredentialBlobSize];
            Marshal.Copy(cred.CredentialBlob, bytes, 0, bytes.Length);
            try
            {
                return System.Text.Encoding.Unicode.GetString(bytes);
            }
            finally
            {
                Array.Clear(bytes);
            }
        }
        finally
        {
            CredFree(ptr);
        }
    }
}

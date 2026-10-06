using System.Security.AccessControl;
using System.Security.Principal;
using CryptEscrow.Services;
using FluentAssertions;
using Xunit;

namespace CryptEscrow.Tests.Services;

/// <summary>
/// The SYSTEM-run repair of ProgramData\ManagedEncryption. Setting the folder's owner
/// and ACL needs admin, so the sweep runs here with the ACL step off and the owner
/// lookup supplied by the test.
/// </summary>
public class DataDirectoryGuardTests
{
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier StandardUser = new("S-1-5-21-1004336348-1177238915-682003330-1001");

    /// <summary>A directory junction: what a standard user can create without any privilege.</summary>
    private static void CreateJunction(string link, string target)
    {
        using var process = global::System.Diagnostics.Process.Start(new global::System.Diagnostics.ProcessStartInfo
        {
            FileName = "cmd.exe",
            ArgumentList = { "/c", "mklink", "/J", link, target },
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        })!;
        process.WaitForExit();
        process.ExitCode.Should().Be(0, $"mklink /J {link} should succeed");
    }

    [Fact]
    public void ConfigWrittenBySystemDeploymentIsKept() =>
        DataDirectoryGuard.Decide(isLink: false, System, underLogs: false).Should().Be(DataDirectoryGuard.Action.Keep);

    [Fact]
    public void ConfigWrittenByAdministratorsIsKept() =>
        DataDirectoryGuard.Decide(isLink: false, Administrators, underLogs: false).Should().Be(DataDirectoryGuard.Action.Keep);

    [Fact]
    public void FileFromAStandardUserIsRemoved() =>
        DataDirectoryGuard.Decide(isLink: false, StandardUser, underLogs: false).Should().Be(DataDirectoryGuard.Action.Remove);

    [Fact]
    public void LogFromAStandardUserIsReclaimed() =>
        DataDirectoryGuard.Decide(isLink: false, StandardUser, underLogs: true).Should().Be(DataDirectoryGuard.Action.Reclaim);

    [Fact]
    public void LinkIsRemovedWhoeverOwnsIt() =>
        DataDirectoryGuard.Decide(isLink: true, System, underLogs: false).Should().Be(DataDirectoryGuard.Action.Remove);

    [Fact]
    public void SystemOwnedConfigStaysTrustedUnderTheRepairedFolderAcl()
    {
        // What a SYSTEM-run deployment script leaves behind once the folder's ACL is
        // repaired: owner SYSTEM, entries inherited from the locked folder.
        var file = new FileSecurity();
        file.SetOwner(System);
        file.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl, AccessControlType.Allow));
        file.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, AccessControlType.Allow));
        file.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.ReadAndExecute, AccessControlType.Allow));

        TrustedFile.Evaluate("config.yaml", file).Should().BeNull();
    }

    [Fact]
    public void SweepKeepsAdministratorFilesAndRemovesTheRestWithoutFollowingLinks()
    {
        var root = Path.Combine(Path.GetTempPath(), "crypt-escrow-tests", Guid.NewGuid().ToString("N"));
        var data = Path.Combine(root, "ManagedEncryption");
        var outside = Path.Combine(root, "outside");
        Directory.CreateDirectory(Path.Combine(data, "planted"));
        Directory.CreateDirectory(outside);
        try
        {
            File.WriteAllText(Path.Combine(outside, "precious.txt"), "keep");
            File.WriteAllText(Path.Combine(data, "config.yaml"), "server:\n  url: https://example.com\n");
            File.WriteAllText(Path.Combine(data, "last_escrow.txt"), DateTimeOffset.UtcNow.ToString("o"));
            File.WriteAllText(Path.Combine(data, "planted", "config.yaml"), "x");
            CreateJunction(Path.Combine(data, "link"), outside);
            CreateJunction(Path.Combine(data, "planted", "nested-link"), outside);

            // config.yaml was written by a SYSTEM deployment; the rest by a standard user.
            SecurityIdentifier OwnerOf(FileSystemInfo entry) =>
                entry.Name == "config.yaml" && entry is FileInfo f && f.DirectoryName == data ? System : StandardUser;

            var notes = DataDirectoryGuard.Secure(data, lockAcl: false, ownerOf: OwnerOf);

            File.Exists(Path.Combine(data, "config.yaml")).Should().BeTrue();
            File.Exists(Path.Combine(data, "last_escrow.txt")).Should().BeFalse();
            Directory.Exists(Path.Combine(data, "planted")).Should().BeFalse();
            Directory.Exists(Path.Combine(data, "link")).Should().BeFalse();
            File.Exists(Path.Combine(outside, "precious.txt")).Should().BeTrue("links are removed, never followed");
            notes.Should().Contain(n => n.Contains("a link"));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void LinkInPlaceOfTheFolderIsReplacedNotFollowed()
    {
        var root = Path.Combine(Path.GetTempPath(), "crypt-escrow-tests", Guid.NewGuid().ToString("N"));
        var data = Path.Combine(root, "ManagedEncryption");
        var outside = Path.Combine(root, "outside");
        Directory.CreateDirectory(outside);
        try
        {
            File.WriteAllText(Path.Combine(outside, "precious.txt"), "keep");
            CreateJunction(data, outside);

            var notes = DataDirectoryGuard.Secure(data, lockAcl: false, ownerOf: _ => System);

            new DirectoryInfo(data).Attributes.HasFlag(FileAttributes.ReparsePoint).Should().BeFalse();
            File.Exists(Path.Combine(outside, "precious.txt")).Should().BeTrue();
            notes.Should().Contain(n => n.Contains("was a link"));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}

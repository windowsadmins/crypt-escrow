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
    private static readonly SecurityIdentifier EntraUser = new("S-1-12-1-1111111111-2222222222-3333333333-4444444444");

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

    private static DataDirectoryGuard.Action Decide(SecurityIdentifier owner, bool wasLocked = false,
        bool knownAdmin = false, bool underLogs = false, bool isLink = false) =>
        DataDirectoryGuard.Decide(isLink, owner, underLogs, wasLocked, knownAdmin);

    [Fact]
    public void ConfigWrittenBySystemDeploymentIsKept() =>
        Decide(System).Should().Be(DataDirectoryGuard.Action.Keep);

    [Fact]
    public void ConfigWrittenByAdministratorsIsKept() =>
        Decide(Administrators).Should().Be(DataDirectoryGuard.Action.Keep);

    [Fact]
    public void IndividualAdministratorOwnerIsNormalisedNotRemoved() =>
        Decide(StandardUser, knownAdmin: true).Should().Be(DataDirectoryGuard.Action.Normalise);

    [Fact]
    public void AnyOwnerInAnAlreadyLockedFolderIsNormalised() =>
        Decide(StandardUser, wasLocked: true).Should().Be(DataDirectoryGuard.Action.Normalise);

    [Fact]
    public void UnresolvableOwnerOnFirstLockdownIsQuarantined() =>
        Decide(StandardUser).Should().Be(DataDirectoryGuard.Action.Quarantine);

    [Fact]
    public void LogsAreNormalisedWhoeverOwnsThem() =>
        Decide(StandardUser, underLogs: true).Should().Be(DataDirectoryGuard.Action.Normalise);

    [Fact]
    public void LinkIsRemovedWhoeverOwnsIt()
    {
        Decide(System, isLink: true).Should().Be(DataDirectoryGuard.Action.RemoveLink);
        Decide(StandardUser, wasLocked: true, isLink: true).Should().Be(DataDirectoryGuard.Action.RemoveLink);
    }

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
    public void FirstLockdownQuarantinesUnresolvableFilesAndNeverFollowsLinks()
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

            var stamp = new DateTime(2026, 10, 6, 9, 30, 0);
            var notes = DataDirectoryGuard.Secure(data, lockAcl: false, ownerOf: OwnerOf, folderWasLocked: false, now: stamp);

            var quarantine = Path.Combine(data, DataDirectoryGuard.QuarantineFolder, "20261006-093000");
            File.Exists(Path.Combine(data, "config.yaml")).Should().BeTrue();
            File.Exists(Path.Combine(data, "last_escrow.txt")).Should().BeFalse();
            File.Exists(Path.Combine(quarantine, "last_escrow.txt")).Should().BeTrue("quarantine moves, it never deletes");
            File.Exists(Path.Combine(quarantine, "planted", "config.yaml")).Should().BeTrue();
            Directory.Exists(Path.Combine(quarantine, "planted", "nested-link")).Should().BeFalse("links are removed before a move");
            Directory.Exists(Path.Combine(data, "link")).Should().BeFalse();
            File.Exists(Path.Combine(outside, "precious.txt")).Should().BeTrue("links are removed, never followed");
            notes.Should().Contain(n => n.StartsWith("Quarantined") && n.Contains("last_escrow.txt"));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void LaterRunsKeepIndividuallyOwnedFilesInALockedFolder()
    {
        var root = Path.Combine(Path.GetTempPath(), "crypt-escrow-tests", Guid.NewGuid().ToString("N"));
        var data = Path.Combine(root, "ManagedEncryption");
        Directory.CreateDirectory(data);
        try
        {
            // An Entra ID administrator wrote it after the folder was locked.
            File.WriteAllText(Path.Combine(data, "config.yaml"), "server:\n  url: https://example.com\n");

            var notes = DataDirectoryGuard.Secure(data, lockAcl: false, ownerOf: _ => EntraUser, folderWasLocked: true);

            File.Exists(Path.Combine(data, "config.yaml")).Should().BeTrue();
            Directory.Exists(Path.Combine(data, DataDirectoryGuard.QuarantineFolder)).Should().BeFalse();
            notes.Should().NotContain(n => n.StartsWith("Quarantined"));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void QuarantinedFilesAreLeftAloneOnLaterRuns()
    {
        var root = Path.Combine(Path.GetTempPath(), "crypt-escrow-tests", Guid.NewGuid().ToString("N"));
        var data = Path.Combine(root, "ManagedEncryption");
        var held = Path.Combine(data, DataDirectoryGuard.QuarantineFolder, "20261006-093000");
        Directory.CreateDirectory(held);
        try
        {
            File.WriteAllText(Path.Combine(held, "config.yaml"), "x");

            DataDirectoryGuard.Secure(data, lockAcl: false, ownerOf: _ => StandardUser, folderWasLocked: false,
                now: new DateTime(2026, 10, 7));

            File.Exists(Path.Combine(held, "config.yaml")).Should().BeTrue();
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

            var notes = DataDirectoryGuard.Secure(data, lockAcl: false, ownerOf: _ => System, folderWasLocked: false);

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

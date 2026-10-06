using System.Security.AccessControl;
using System.Security.Principal;
using CryptEscrow.Services;
using FluentAssertions;
using Xunit;

namespace CryptEscrow.Tests.Services;

/// <summary>
/// The ACL check that decides whether a SYSTEM run may trust a file under ProgramData.
/// Most cases build the security descriptor in memory, so they run without admin; one
/// checks a real file the test user created.
/// </summary>
[Collection(GlobalStateCollection.Name)]
public class TrustedFileTests
{
    private static readonly SecurityIdentifier EntraAdmin = new("S-1-12-1-1111111111-2222222222-3333333333-4444444444");

    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier AuthenticatedUsers = new(WellKnownSidType.AuthenticatedUserSid, null);
    private static readonly SecurityIdentifier Everyone = new(WellKnownSidType.WorldSid, null);
    private static readonly SecurityIdentifier CreatorOwner = new(WellKnownSidType.CreatorOwnerSid, null);

    private const InheritanceFlags All = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

    /// <summary>The ACL the installer sets: SYSTEM and Administrators full control, Users read.</summary>
    private static DirectorySecurity LockedFolder(SecurityIdentifier? owner = null)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(owner ?? Administrators);
        security.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl, All, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, All, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.ReadAndExecute, All, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    private static FileSecurity LockedFile(SecurityIdentifier? owner = null)
    {
        var security = new FileSecurity();
        security.SetOwner(owner ?? System);
        security.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.ReadAndExecute, AccessControlType.Allow));
        return security;
    }

    [Fact]
    public void InstallerAclIsTrusted()
    {
        TrustedFile.Evaluate("folder", LockedFolder()).Should().BeNull();
        TrustedFile.Evaluate("file", LockedFile()).Should().BeNull();
    }

    [Theory]
    [InlineData("S-1-5-18")]
    [InlineData("S-1-5-32-544")]
    [InlineData("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")]
    public void TrustedOwners(string sid) =>
        TrustedFile.IsTrustedAccount(new SecurityIdentifier(sid)).Should().BeTrue();

    [Theory]
    [InlineData("S-1-5-32-545")]
    [InlineData("S-1-5-11")]
    [InlineData("S-1-1-0")]
    [InlineData("S-1-5-21-1004336348-1177238915-682003330-1001")]
    public void UntrustedOwners(string sid) =>
        TrustedFile.IsTrustedAccount(new SecurityIdentifier(sid)).Should().BeFalse();

    [Fact]
    public void FileOwnedByAStandardUserIsNotTrusted()
    {
        var user = new SecurityIdentifier("S-1-5-21-1004336348-1177238915-682003330-1001");

        TrustedFile.Evaluate("config.yaml", LockedFile(owner: user))
            .Should().Contain("owned by").And.Contain(user.Value);
    }

    [Theory]
    [InlineData(FileSystemRights.WriteData)]
    [InlineData(FileSystemRights.AppendData)]
    [InlineData(FileSystemRights.Modify)]
    [InlineData(FileSystemRights.FullControl)]
    [InlineData(FileSystemRights.Delete)]
    [InlineData(FileSystemRights.ChangePermissions)]
    [InlineData(FileSystemRights.TakeOwnership)]
    public void FileWritableByUsersIsNotTrusted(FileSystemRights rights)
    {
        var security = LockedFile();
        security.AddAccessRule(new FileSystemAccessRule(Users, rights, AccessControlType.Allow));

        TrustedFile.Evaluate("config.yaml", security).Should().Contain(Users.Value);
    }

    [Fact]
    public void FileWritableByEveryoneOrAuthenticatedUsersIsNotTrusted()
    {
        var everyone = LockedFile();
        everyone.AddAccessRule(new FileSystemAccessRule(Everyone, FileSystemRights.Write, AccessControlType.Allow));
        var authenticated = LockedFile();
        authenticated.AddAccessRule(new FileSystemAccessRule(AuthenticatedUsers, FileSystemRights.Modify, AccessControlType.Allow));

        TrustedFile.Evaluate("config.yaml", everyone).Should().NotBeNull();
        TrustedFile.Evaluate("config.yaml", authenticated).Should().NotBeNull();
    }

    [Fact]
    public void FolderWhereUsersCanCreateFilesIsNotTrusted()
    {
        // ProgramData's own default: Users may create files and folders below it.
        var security = LockedFolder();
        security.AddAccessRule(new FileSystemAccessRule(Users,
            FileSystemRights.CreateFiles | FileSystemRights.CreateDirectories,
            InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));

        TrustedFile.Evaluate("folder", security).Should().Contain(Users.Value);
    }

    [Fact]
    public void FolderWhereUsersCanDeleteChildrenIsNotTrusted()
    {
        var security = LockedFolder();
        security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.DeleteSubdirectoriesAndFiles, AccessControlType.Allow));

        TrustedFile.Evaluate("folder", security).Should().NotBeNull();
    }

    [Fact]
    public void FolderOwnedByAStandardUserIsNotTrusted()
    {
        var user = new SecurityIdentifier("S-1-5-21-1004336348-1177238915-682003330-1001");

        TrustedFile.Evaluate("folder", LockedFolder(owner: user)).Should().Contain("owned by");
    }

    [Fact]
    public void InheritOnlyEntriesDoNotApplyToTheObject()
    {
        // CREATOR OWNER full control on children is what ProgramData carries; it grants
        // nothing on the folder itself.
        var security = LockedFolder();
        security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.Modify,
            All, PropagationFlags.InheritOnly, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(CreatorOwner, FileSystemRights.FullControl,
            All, PropagationFlags.InheritOnly, AccessControlType.Allow));

        TrustedFile.Evaluate("folder", security).Should().BeNull();
    }

    [Fact]
    public void IndividualOwnerInALockedFolderIsTrusted()
    {
        // Only an administrator can create a file in a locked folder, so the owner is not
        // held against it, even one the tool cannot resolve.
        TrustedFile.Evaluate("config.yaml", LockedFile(owner: EntraAdmin), ownerVouchedByParent: true)
            .Should().BeNull();
    }

    [Fact]
    public void IndividualOwnerDoesNotExcuseAWriteGrant()
    {
        var security = LockedFile(owner: EntraAdmin);
        security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.Modify, AccessControlType.Allow));

        TrustedFile.Evaluate("config.yaml", security, ownerVouchedByParent: true).Should().Contain(Users.Value);
    }

    [Theory]
    [InlineData(FileSystemRights.Delete)]
    [InlineData(FileSystemRights.ChangePermissions)]
    [InlineData(FileSystemRights.TakeOwnership)]
    public void DeleteWriteDacAndWriteOwnerGrantsAreRefused(FileSystemRights rights)
    {
        var security = LockedFile(owner: EntraAdmin);
        security.AddAccessRule(new FileSystemAccessRule(AuthenticatedUsers, rights, AccessControlType.Allow));

        TrustedFile.Evaluate("config.yaml", security, ownerVouchedByParent: true).Should().NotBeNull();
    }

    [Fact]
    public void FolderOwnedByAKnownAdministratorIsTrusted()
    {
        var previous = AdminMembership.Override;
        AdminMembership.Override = sid => sid == EntraAdmin;
        try
        {
            TrustedFile.Evaluate("folder", LockedFolder(owner: EntraAdmin)).Should().BeNull();
        }
        finally
        {
            AdminMembership.Override = previous;
        }
    }

    [Fact]
    public void FolderOwnedByAnUnresolvableAccountIsNotTrusted()
    {
        var previous = AdminMembership.Override;
        AdminMembership.Override = _ => false;
        try
        {
            TrustedFile.Evaluate("folder", LockedFolder(owner: EntraAdmin)).Should().Contain("owned by");
        }
        finally
        {
            AdminMembership.Override = previous;
        }
    }

    [Fact]
    public void WriteGrantToAKnownAdministratorIsAllowed()
    {
        var previous = AdminMembership.Override;
        AdminMembership.Override = sid => sid == EntraAdmin;
        try
        {
            var security = LockedFile();
            security.AddAccessRule(new FileSystemAccessRule(EntraAdmin, FileSystemRights.FullControl, AccessControlType.Allow));
            TrustedFile.Evaluate("config.yaml", security).Should().BeNull();
        }
        finally
        {
            AdminMembership.Override = previous;
        }
    }

    [Fact]
    public void DenyEntriesAreNotWriteGrants()
    {
        var security = LockedFile();
        security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.Write, AccessControlType.Deny));

        TrustedFile.Evaluate("config.yaml", security).Should().BeNull();
    }

    [Fact]
    public void FileCreatedByTheTestUserIsNotTrusted()
    {
        // A file in a temp folder is owned by, and writable by, the account running the
        // tests, which is never SYSTEM or the Administrators group.
        var dir = Path.Combine(Path.GetTempPath(), "crypt-escrow-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "config.yaml");
            File.WriteAllText(path, "server:\n  url: https://example.com\n");

            TrustedFile.WhyUntrusted(path).Should().NotBeNull();
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void MissingFileFailsClosed() =>
        TrustedFile.WhyUntrusted(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "config.yaml"))
            .Should().NotBeNull();
}

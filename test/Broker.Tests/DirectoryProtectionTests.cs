using System.Security.AccessControl;
using System.Security.Principal;
using Broker.Core;
using Xunit;

namespace Broker.Tests;

public class DirectoryProtectionTests : IDisposable
{
    private readonly string _testDir;

    public DirectoryProtectionTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), $"mcp-dir-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testDir);
    }

    [Fact]
    public void VerifyProtectedSucceedsOnRestrictedDirectory()
    {
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        const PropagationFlags prop = PropagationFlags.None;

        sec.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl, inherit, prop, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(
            WindowsIdentity.GetCurrent().User!,
            FileSystemRights.FullControl, inherit, prop, AccessControlType.Allow));

        new DirectoryInfo(_testDir).SetAccessControl(sec);

        // Verification must pass on properly restricted directory
        DirectoryProtection.VerifyProtected(_testDir);
    }

    [Fact]
    public void VerifyProtectedFailsWhenBroadPrincipalHasWriteAccess()
    {
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        const PropagationFlags prop = PropagationFlags.None;

        sec.AddAccessRule(new FileSystemAccessRule(
            WindowsIdentity.GetCurrent().User!,
            FileSystemRights.FullControl, inherit, prop, AccessControlType.Allow));

        // Grant write to BUILTIN\Users
        sec.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            FileSystemRights.Write | FileSystemRights.CreateFiles, inherit, prop, AccessControlType.Allow));

        new DirectoryInfo(_testDir).SetAccessControl(sec);

        var ex = Assert.Throws<InvalidOperationException>(() => DirectoryProtection.VerifyProtected(_testDir));
        Assert.Contains("broad principal", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    public void Dispose()
    {
        try { Directory.Delete(_testDir, recursive: true); } catch { }
    }
}


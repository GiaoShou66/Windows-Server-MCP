using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Broker.Core;

/// <summary>
/// Creates broker-owned directories with a restrictive ACL instead of inheriting the
/// parent's.
///
/// The audit and transcript directories are created under C:\ by default. On a stock
/// Windows installation C:\ carries an inheritable BUILTIN\Users:(M) ACE, so a directory
/// created with default inheritance is writable by every local user — which would let any
/// local account rewrite or delete the audit trail the broker is supposed to produce.
/// </summary>
[SupportedOSPlatform("windows")]
public static class DirectoryProtection
{
    /// <summary>
    /// Creates <paramref name="path"/> if missing and resets it to an explicit allow-list:
    /// SYSTEM and Administrators full control, plus <paramref name="serviceIdentity"/> if
    /// given. Inheritance from the parent is removed so a broad parent ACE cannot re-apply.
    /// </summary>
    public static void EnsureProtected(string path, string? serviceIdentity = null)
    {
        var dir = new DirectoryInfo(path);
        if (!dir.Exists) dir.Create();

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        const PropagationFlags noPropagation = PropagationFlags.None;

        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, inherit, noPropagation, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl, inherit, noPropagation, AccessControlType.Allow));

        if (!string.IsNullOrWhiteSpace(serviceIdentity))
        {
            security.AddAccessRule(new FileSystemAccessRule(
                serviceIdentity, FileSystemRights.Modify, inherit, noPropagation, AccessControlType.Allow));
        }

        dir.SetAccessControl(security);
    }
}

using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Broker.Core;

/// <summary>
/// Manages directory ACL verification at runtime and configuration during elevated setup.
///
/// Under H2, setting ACLs requires WRITE_DAC which low-privilege service accounts (like gMSAs)
/// lack. Therefore, ACL configuration is performed during elevated setup (install-service.ps1),
/// while the broker service and audit log at runtime only VERIFY that the directory is not
/// writable by broad principals (failing closed if BUILTIN\Users, Everyone, etc. can modify it).
/// </summary>
[SupportedOSPlatform("windows")]
public static class DirectoryProtection
{
    private static readonly HashSet<SecurityIdentifier> BroadSids = new()
    {
        new SecurityIdentifier(WellKnownSidType.WorldSid, null),                   // Everyone (S-1-1-0)
        new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),       // Authenticated Users (S-1-5-11)
        new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),            // BUILTIN\Users (S-1-5-32-545)
        new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),             // Interactive (S-1-5-4)
        new SecurityIdentifier(WellKnownSidType.AnonymousSid, null),               // Anonymous (S-1-5-7)
        new SecurityIdentifier(WellKnownSidType.NetworkSid, null)                  // Network (S-1-5-2)
    };

    private const FileSystemRights DangerousWriteRights =
        FileSystemRights.Write |
        FileSystemRights.Modify |
        FileSystemRights.FullControl |
        FileSystemRights.WriteData |
        FileSystemRights.CreateFiles |
        FileSystemRights.CreateDirectories;

    /// <summary>
    /// Runtime verification: checks that <paramref name="path"/> exists and is not writable
    /// by broad local/domain principals. Does not call SetAccessControl and does not require WRITE_DAC.
    /// </summary>
    public static void VerifyProtected(string path)
    {
        var dir = new DirectoryInfo(path);
        if (!dir.Exists)
        {
            try { dir.Create(); }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Directory '{path}' does not exist and could not be created: {ex.Message}", ex);
            }
        }

        var tempRoot = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (string.Equals(dir.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), tempRoot, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        DirectorySecurity security;
        try
        {
            security = dir.GetAccessControl(AccessControlSections.Access);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Unable to inspect ACL for directory '{path}': {ex.Message}", ex);
        }

        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow &&
                (rule.FileSystemRights & DangerousWriteRights) != 0 &&
                rule.IdentityReference is SecurityIdentifier sid &&
                BroadSids.Contains(sid))
            {
                throw new InvalidOperationException(
                    $"Directory '{path}' security verification failed: broad principal '{rule.IdentityReference.Value}' has write/modify permissions. " +
                    "Audit and transcript directories must be restricted to administrators and service identity during elevated setup.");
            }
        }
    }

    /// <summary>
    /// Setup-time configuration: creates <paramref name="path"/> if missing and resets it to an
    /// explicit allow-list: SYSTEM and Administrators full control, plus <paramref name="serviceIdentity"/>
    /// if given. Removes inheritance so parent ACEs cannot re-apply.
    /// </summary>
    public static void ConfigureProtectedAcl(string path, string? serviceIdentity = null)
    {
        var dir = new DirectoryInfo(path);
        if (!dir.Exists) dir.Create();

        var tempRoot = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (string.Equals(dir.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), tempRoot, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

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

        var current = WindowsIdentity.GetCurrent().User;
        if (current is not null)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                current, FileSystemRights.FullControl, inherit, noPropagation, AccessControlType.Allow));
        }

        if (!string.IsNullOrWhiteSpace(serviceIdentity))
        {
            security.AddAccessRule(new FileSystemAccessRule(
                serviceIdentity, FileSystemRights.Modify, inherit, noPropagation, AccessControlType.Allow));
        }

        dir.SetAccessControl(security);
    }

    /// <summary>
    /// Backward-compatibility helper: verifies first; if missing or configuration is required
    /// and running with permission to set DACL, configures it.
    /// </summary>
    public static void EnsureProtected(string path, string? serviceIdentity = null)
    {
        try
        {
            ConfigureProtectedAcl(path, serviceIdentity);
        }
        catch (UnauthorizedAccessException)
        {
            // Running as non-admin / without WRITE_DAC (e.g. gMSA runtime): fallback to verification only.
        }

        VerifyProtected(path);
    }
}

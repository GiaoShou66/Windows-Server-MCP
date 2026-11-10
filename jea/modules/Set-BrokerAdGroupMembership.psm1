#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Write: add or remove a user from a domain group. Reversible.
.NOTES
  Privileged groups (Domain Admins, Enterprise Admins, Administrators — the same set the
  manifest's workflowPolicies.privilegedAdGroups names) are denied inside the wrapper
  regardless of parameters. Membership changes to these groups are high-blast-radius
  privilege escalation and are deliberately out of scope for a write-tier toggle tool.
#>
function Set-BrokerAdGroupMembership {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[a-zA-Z0-9 ._-]{1,64}$')]
        [string] $GroupName,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[a-zA-Z0-9._-]{1,64}$')]
        [string] $MemberSamAccountName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Add', 'Remove')]
        [string] $Action
    )

    # Denylist covers the manifest's workflowPolicies.privilegedAdGroups plus the other
    # built-in groups that confer equivalent or adjacent control. Explicit list because the
    # JEA session runs in NoLanguage mode and cannot read policy at runtime.
    $deniedGroups = @(
        'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
        'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators',
        'DnsAdmins', 'Group Policy Creator Owners', 'Enterprise Key Admins', 'Key Admins',
        'Domain Controllers', 'Read-only Domain Controllers'
    )
    if ($deniedGroups -contains $GroupName) {
        throw "Membership changes to group '$GroupName' are denied by policy (privileged group)."
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    # Resolve the group by exact identity without building an LDAP filter string from
    # user input. Get-ADGroup -Identity resolves by exact SamAccountName, Name, SID, GUID, or DN.
    $group = try {
        Get-ADGroup -Identity $GroupName -Properties ObjectGuid, SID, Name, SamAccountName, adminCount, MemberOf -ErrorAction Stop
    }
    catch {
        throw "Group '$GroupName' not found."
    }
    if (-not $group) {
        throw "Group '$GroupName' not found."
    }

    # H4: Deny by well-known privileged RIDs and Built-in SIDs
    $deniedRidsPattern = '-(512|516|518|519|520|498|521)$'
    $deniedBuiltinSids = @(
        'S-1-5-32-544',
        'S-1-5-32-548',
        'S-1-5-32-549',
        'S-1-5-32-550',
        'S-1-5-32-551'
    )

    $groupSid = $group.SID.Value
    if ($groupSid -match $deniedRidsPattern -or $deniedBuiltinSids -contains $groupSid) {
        throw "Membership changes to group '$GroupName' are denied by policy (privileged group SID: $groupSid)."
    }

    # H4: Deny by adminCount = 1 (Active Directory AdminSDHolder / SDProp protected object)
    if ($group.PSObject.Properties['adminCount'] -and ($group.adminCount -as [int]) -eq 1) {
        throw "Membership changes to group '$GroupName' are denied by policy (adminCount=1 protected group)."
    }

    # Defense-in-depth: re-verify resolved group Name and SamAccountName against the denylist
    if ($deniedGroups -contains $group.Name -or $deniedGroups -contains $group.SamAccountName) {
        throw "Membership changes to group '$GroupName' are denied by policy (privileged group)."
    }

    # H4: Transitive nesting check into protected groups
    if ($group.MemberOf -and $group.MemberOf.Count -gt 0) {
        foreach ($parentDn in $group.MemberOf) {
            $parentGroup = Get-ADGroup -Identity $parentDn -Properties ObjectGuid, SID, Name, SamAccountName, adminCount -ErrorAction SilentlyContinue
            if ($parentGroup) {
                $pSid = $parentGroup.SID.Value
                if ($pSid -match $deniedRidsPattern -or
                    $deniedBuiltinSids -contains $pSid -or
                    $deniedGroups -contains $parentGroup.Name -or
                    ($parentGroup.PSObject.Properties['adminCount'] -and ($parentGroup.adminCount -as [int]) -eq 1)) {
                    throw "Membership changes to group '$GroupName' are denied by policy (transitively nested in protected group '$($parentGroup.Name)')."
                }
            }
        }
    }

    $member = Get-ADUser -SamAccountName $MemberSamAccountName -Properties SamAccountName, ObjectGuid, SID -ErrorAction Stop

    # Privileged RIDs: -500 built-in Administrator, -502 krbtgt. Refuse to make either a member.
    if ($member.SID.Value -match '-500$' -or $member.SID.Value -match '-502$') {
        throw "Adding '$MemberSamAccountName' to a group is denied by policy (privileged account)."
    }

    if ($Action -eq 'Add') {
        Add-ADGroupMember -Identity $group.ObjectGuid -Members $member.ObjectGuid -ErrorAction Stop
    }
    else {
        Remove-ADGroupMember -Identity $group.ObjectGuid -Members $member.ObjectGuid -Confirm:$false -ErrorAction Stop
    }

    [pscustomobject]@{
        GroupName            = $group.Name
        MemberSamAccountName = $member.SamAccountName
        Action               = $Action
    }
}

Export-ModuleMember -Function Set-BrokerAdGroupMembership

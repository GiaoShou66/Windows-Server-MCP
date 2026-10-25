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

    # Resolve by explicit name/SamAccountName so a caller cannot pass a group SID
    # (e.g. S-1-5-32-544 = Administrators) or a DN and slip past the name denylist.
    $group = Get-ADGroup -Filter 'Name -eq $GroupName' -Properties ObjectGuid, SID -ErrorAction Stop |
        Select-Object -First 1
    if (-not $group) {
        throw "Group '$GroupName' not found."
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

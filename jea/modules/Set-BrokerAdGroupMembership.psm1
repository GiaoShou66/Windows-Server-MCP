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

    $deniedGroups = @('Domain Admins', 'Enterprise Admins', 'Administrators', 'Schema Admins')
    if ($deniedGroups -contains $GroupName) {
        throw "Membership changes to group '$GroupName' are denied by policy (privileged group)."
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    Get-ADGroup -Identity $GroupName -ErrorAction Stop | Out-Null
    Get-ADUser -Identity $MemberSamAccountName -ErrorAction Stop | Out-Null

    if ($Action -eq 'Add') {
        Add-ADGroupMember -Identity $GroupName -Members $MemberSamAccountName -ErrorAction Stop
    }
    else {
        Remove-ADGroupMember -Identity $GroupName -Members $MemberSamAccountName -Confirm:$false -ErrorAction Stop
    }

    [pscustomobject]@{
        GroupName            = $GroupName
        MemberSamAccountName = $MemberSamAccountName
        Action               = $Action
    }
}

Export-ModuleMember -Function Set-BrokerAdGroupMembership

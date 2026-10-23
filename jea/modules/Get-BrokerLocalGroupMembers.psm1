#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate members of a built-in local group.
.NOTES
  GroupName is ValidateSet-constrained in the generated .psrc to a fixed list of
  well-known built-in groups, matching the manifest's enum allowlist.
#>
function Get-BrokerLocalGroupMembers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Administrators', 'Users', 'Remote Desktop Users', 'Backup Operators', 'Power Users', 'Guests')]
        [string] $GroupName
    )

    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop

    Get-LocalGroupMember -Group $GroupName -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Name            = $_.Name
            ObjectClass     = $_.ObjectClass.ToString()
            PrincipalSource = $_.PrincipalSource.ToString()
        }
    }
}

Export-ModuleMember -Function Get-BrokerLocalGroupMembers

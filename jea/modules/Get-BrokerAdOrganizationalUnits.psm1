#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate organizational units in the domain.
.NOTES
  ResultSetSize bounds the query server-side — see Get-BrokerAdComputers.psm1 for why.
#>
function Get-BrokerAdOrganizationalUnits {
    [CmdletBinding()]
    param()

    Import-Module ActiveDirectory -ErrorAction Stop

    Get-ADOrganizationalUnit -Filter * -ResultSetSize 1000 -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Name              = $_.Name
            DistinguishedName = $_.DistinguishedName
        }
    }
}

Export-ModuleMember -Function Get-BrokerAdOrganizationalUnits

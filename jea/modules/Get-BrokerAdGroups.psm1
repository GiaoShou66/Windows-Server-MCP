#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate AD security/distribution groups.
.NOTES
  Exposed through the McpBroker.ReadDirectory JEA endpoint (gMSA identity, real Kerberos).
  ResultSetSize bounds the query server-side — see Get-BrokerAdComputers.psm1 for why.
#>
function Get-BrokerAdGroups {
    [CmdletBinding()]
    param()

    Import-Module ActiveDirectory -ErrorAction Stop

    Get-ADGroup -Filter * -ResultSetSize 1000 -Properties GroupCategory, GroupScope, objectSid -ErrorAction Stop |
        ForEach-Object {
            [pscustomobject]@{
                Name          = $_.Name
                GroupCategory = $_.GroupCategory.ToString()
                GroupScope    = $_.GroupScope.ToString()
                objectSid     = $_.objectSid.Value
            }
        }
}

Export-ModuleMember -Function Get-BrokerAdGroups

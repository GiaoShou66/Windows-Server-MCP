#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate local (non-domain) groups on this host.
.NOTES
  SID is masked broker-side after return.
#>
function Get-BrokerLocalGroups {
    [CmdletBinding()]
    param()

    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop

    Get-LocalGroup -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Name        = $_.Name
            Description = $_.Description
            SID         = $_.SID.Value
        }
    }
}

Export-ModuleMember -Function Get-BrokerLocalGroups

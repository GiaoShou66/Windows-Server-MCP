#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate AD FS relying party trusts on this server.
#>
function Get-BrokerAdfsRelyingParties {
    [CmdletBinding()]
    param()

    Import-Module ADFS -ErrorAction Stop

    Get-AdfsRelyingPartyTrust -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Name       = $_.Name
            Identifier = $_.Identifier
            Enabled    = $_.Enabled
        }
    }
}

Export-ModuleMember -Function Get-BrokerAdfsRelyingParties

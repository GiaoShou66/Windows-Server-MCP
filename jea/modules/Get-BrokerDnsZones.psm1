#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate zones hosted on this DNS server.
#>
function Get-BrokerDnsZones {
    [CmdletBinding()]
    param()

    Import-Module DnsServer -ErrorAction Stop

    Get-DnsServerZone -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            ZoneName            = $_.ZoneName
            ZoneType            = $_.ZoneType.ToString()
            IsDsIntegrated      = $_.IsDsIntegrated
            IsReverseLookupZone = $_.IsReverseLookupZone
        }
    }
}

Export-ModuleMember -Function Get-BrokerDnsZones

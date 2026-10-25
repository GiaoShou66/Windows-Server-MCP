#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: return VPN/DirectAccess role status (RRAS portion of NPAS).
#>
function Get-BrokerRemoteAccessStatus {
    [CmdletBinding()]
    param()

    Import-Module RemoteAccess -ErrorAction Stop

    $ra = Get-RemoteAccess -ErrorAction Stop
    [pscustomobject]@{
        VpnStatus     = $ra.VpnStatus.ToString()
        DAStatus      = $ra.DAStatus.ToString()
        RoutingStatus = $ra.RoutingStatus.ToString()
    }
}

Export-ModuleMember -Function Get-BrokerRemoteAccessStatus

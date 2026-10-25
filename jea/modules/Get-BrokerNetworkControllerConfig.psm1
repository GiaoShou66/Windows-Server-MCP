#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: return this Network Controller's REST endpoint and node configuration.
#>
function Get-BrokerNetworkControllerConfig {
    [CmdletBinding()]
    param()

    Import-Module NetworkController -ErrorAction Stop

    $nc = Get-NetworkController -ErrorAction Stop
    [pscustomobject]@{
        RestIpAddress     = $nc.RestIPAddress
        Node              = $nc.Node
        ServerCertificate = $nc.ServerCertificate.Thumbprint
    }
}

Export-ModuleMember -Function Get-BrokerNetworkControllerConfig

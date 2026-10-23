#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: return this Network Controller's REST endpoint and node configuration.
.NOTES
  Node is projected to the node NAMES only. Passing $nc.Node through whole would hand the broker
  every property of every node object (a remote call deserializes the full object graph, and
  the broker flattens all of it into the response). Not exercised against a real Network
  Controller in this repository: StrictMode makes a missing 'Name' property a visible error
  rather than a silent leak.
#>
function Get-BrokerNetworkControllerConfig {
    [CmdletBinding()]
    param()

    Import-Module NetworkController -ErrorAction Stop

    $nc = Get-NetworkController -ErrorAction Stop
    [pscustomobject]@{
        RestIpAddress     = $nc.RestIPAddress
        Node              = @($nc.Node | ForEach-Object { [string] $_.Name })
        ServerCertificate = $nc.ServerCertificate.Thumbprint
    }
}

Export-ModuleMember -Function Get-BrokerNetworkControllerConfig

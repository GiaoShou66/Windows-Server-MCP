#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate Network Load Balancing clusters configured on this host.
#>
function Get-BrokerNlbClusters {
    [CmdletBinding()]
    param()

    Import-Module NetworkLoadBalancingClusters -ErrorAction Stop

    Get-NlbCluster -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            ClusterName = $_.InterfaceName
            ClusterIP   = ($_.ClusterIPAddresses -join ',')
            ClusterMode = $_.ClusterOperationMode.ToString()
        }
    }
}

Export-ModuleMember -Function Get-BrokerNlbClusters

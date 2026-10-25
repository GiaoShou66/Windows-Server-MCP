#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate nodes in the local failover cluster.
#>
function Get-BrokerClusterNodes {
    [CmdletBinding()]
    param()

    Import-Module FailoverClusters -ErrorAction Stop

    Get-ClusterNode -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Name          = $_.Name
            State         = $_.State.ToString()
            DynamicWeight = $_.DynamicWeight
        }
    }
}

Export-ModuleMember -Function Get-BrokerClusterNodes

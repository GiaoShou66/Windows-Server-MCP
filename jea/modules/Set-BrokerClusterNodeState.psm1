#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Write: pause or resume a failover cluster node. Reversible. Does not evict/remove it.
#>
function Set-BrokerClusterNodeState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9_.-]{1,80}$')]
        [string] $NodeName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Pause', 'Resume')]
        [string] $Action
    )

    Import-Module FailoverClusters -ErrorAction Stop

    Get-ClusterNode -Name $NodeName -ErrorAction Stop | Out-Null

    if ($Action -eq 'Pause') {
        Suspend-ClusterNode -Name $NodeName -ErrorAction Stop | Out-Null
    }
    else {
        Resume-ClusterNode -Name $NodeName -ErrorAction Stop | Out-Null
    }

    $updated = Get-ClusterNode -Name $NodeName -ErrorAction Stop
    [pscustomobject]@{
        Name  = $updated.Name
        State = $updated.State.ToString()
    }
}

Export-ModuleMember -Function Set-BrokerClusterNodeState

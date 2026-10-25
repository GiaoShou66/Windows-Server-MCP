#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate Storage Spaces pools on this host.
#>
function Get-BrokerStoragePools {
    [CmdletBinding()]
    param()

    Import-Module Storage -ErrorAction Stop

    Get-StoragePool -ErrorAction Stop | Where-Object { -not $_.IsPrimordial } | ForEach-Object {
        [pscustomobject]@{
            FriendlyName   = $_.FriendlyName
            HealthStatus   = $_.HealthStatus.ToString()
            SizeBytes      = $_.Size
            AllocatedBytes = $_.AllocatedSize
        }
    }
}

Export-ModuleMember -Function Get-BrokerStoragePools

#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate physical disks on this host (Storage).
#>
function Get-BrokerDisks {
    [CmdletBinding()]
    param()

    Import-Module Storage -ErrorAction Stop

    Get-Disk -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Number         = $_.Number
            FriendlyName   = $_.FriendlyName
            SizeBytes      = $_.Size
            HealthStatus   = $_.HealthStatus.ToString()
            PartitionStyle = $_.PartitionStyle.ToString()
        }
    }
}

Export-ModuleMember -Function Get-BrokerDisks

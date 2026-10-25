#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate virtual machines on this Hyper-V host.
.NOTES
  Bounded to 500 — a large cluster host can run hundreds of VMs.
#>
function Get-BrokerHyperVVms {
    [CmdletBinding()]
    param()

    Import-Module Hyper-V -ErrorAction Stop

    Get-VM -ErrorAction Stop | Select-Object -First 500 | ForEach-Object {
        [pscustomobject]@{
            Name                = $_.Name
            State               = $_.State.ToString()
            CPUUsage            = $_.CPUUsage
            MemoryAssignedBytes = $_.MemoryAssigned
            Uptime              = $_.Uptime.ToString()
        }
    }
}

Export-ModuleMember -Function Get-BrokerHyperVVms

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

    $count = 0
    foreach ($vm in @(Get-VM -ErrorAction Stop)) {
        if ($null -eq $vm) { continue }
        if ($count -ge 500) { break }
        $count++
        [pscustomobject]@{
            Name                = $vm.Name
            State               = $vm.State.ToString()
            CPUUsage            = $vm.CPUUsage
            MemoryAssignedBytes = $vm.MemoryAssigned
            Uptime              = $vm.Uptime.ToString()
        }
    }
}

Export-ModuleMember -Function Get-BrokerHyperVVms

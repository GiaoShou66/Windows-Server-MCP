#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Write: start or stop a Hyper-V virtual machine. Reversible.
#>
function Set-BrokerHyperVVmState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9 _.-]{1,150}$')]
        [string] $VmName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Start', 'Stop')]
        [string] $Action
    )

    Import-Module Hyper-V -ErrorAction Stop

    Get-VM -Name $VmName -ErrorAction Stop | Out-Null

    if ($Action -eq 'Start') {
        Start-VM -Name $VmName -ErrorAction Stop
    }
    else {
        Stop-VM -Name $VmName -ErrorAction Stop
    }

    $updated = Get-VM -Name $VmName -ErrorAction Stop
    [pscustomobject]@{
        Name  = $updated.Name
        State = $updated.State.ToString()
    }
}

Export-ModuleMember -Function Set-BrokerHyperVVmState

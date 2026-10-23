#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Write: enable or disable a domain computer account. Reversible.
.NOTES
  Domain controllers are denied inside the wrapper, checked live against the current
  DC list (not a static name list) — disabling a DC's computer account is catastrophic.
#>
function Set-BrokerAdComputerEnabled {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[a-zA-Z0-9._-]{1,64}$')]
        [string] $ComputerName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('true', 'false')]
        [string] $Enabled
    )

    Import-Module ActiveDirectory -ErrorAction Stop

    $dcNames = (Get-ADDomainController -Filter * -ErrorAction Stop).Name
    if ($dcNames -contains $ComputerName) {
        throw "Action on computer '$ComputerName' is denied by policy (domain controller)."
    }

    Get-ADComputer -Identity $ComputerName -ErrorAction Stop | Out-Null

    if ($Enabled -eq 'true') {
        Enable-ADAccount -Identity $ComputerName -ErrorAction Stop
    }
    else {
        Disable-ADAccount -Identity $ComputerName -ErrorAction Stop
    }

    $updated = Get-ADComputer -Identity $ComputerName -Properties Enabled -ErrorAction Stop
    [pscustomobject]@{
        Name    = $updated.Name
        Enabled = $updated.Enabled
    }
}

Export-ModuleMember -Function Set-BrokerAdComputerEnabled

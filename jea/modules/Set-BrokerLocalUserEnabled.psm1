#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Write: enable or disable a local (non-domain) user account.
.NOTES
  Reversible. Well-known built-in accounts (Administrator, Guest, DefaultAccount,
  WDAGUtilityAccount) are denied inside the wrapper regardless of parameters.
#>
function Set-BrokerLocalUserEnabled {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9_.-]{1,80}$')]
        [string] $UserName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('true', 'false')]
        [string] $Enabled
    )

    $deniedUsers = @('Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount')
    if ($deniedUsers -contains $UserName) {
        throw "Action on local user '$UserName' is denied by policy (built-in account)."
    }

    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop

    Get-LocalUser -Name $UserName -ErrorAction Stop | Out-Null

    if ($Enabled -eq 'true') {
        Enable-LocalUser -Name $UserName -ErrorAction Stop
    }
    else {
        Disable-LocalUser -Name $UserName -ErrorAction Stop
    }

    $updated = Get-LocalUser -Name $UserName -ErrorAction Stop
    [pscustomobject]@{
        Name    = $updated.Name
        Enabled = $updated.Enabled
    }
}

Export-ModuleMember -Function Set-BrokerLocalUserEnabled

#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Write: start or stop an IIS web or FTP site. Reversible.
#>
function Set-BrokerIisSiteState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9 _.-]{1,150}$')]
        [string] $SiteName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Start', 'Stop')]
        [string] $Action
    )

    Import-Module WebAdministration -ErrorAction Stop

    Get-Website -Name $SiteName -ErrorAction Stop | Out-Null

    if ($Action -eq 'Start') {
        Start-Website -Name $SiteName -ErrorAction Stop
    }
    else {
        Stop-Website -Name $SiteName -ErrorAction Stop
    }

    $updated = Get-Website -Name $SiteName -ErrorAction Stop
    [pscustomobject]@{
        Name  = $updated.Name
        State = $updated.State.ToString()
    }
}

Export-ModuleMember -Function Set-BrokerIisSiteState

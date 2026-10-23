#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Write: set a GPO's enabled/disabled status for computer and/or user settings. Reversible.
#>
function Set-BrokerGpoStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9 _.-]{1,150}$')]
        [string] $GpoName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('AllSettingsEnabled', 'AllSettingsDisabled', 'UserSettingsDisabled', 'ComputerSettingsDisabled')]
        [string] $Status
    )

    Import-Module GroupPolicy -ErrorAction Stop

    Get-GPO -Name $GpoName -ErrorAction Stop | Out-Null

    $updated = Set-GPO -Name $GpoName -Status $Status -ErrorAction Stop
    [pscustomobject]@{
        DisplayName = $updated.DisplayName
        GpoStatus   = $updated.GpoStatus.ToString()
    }
}

Export-ModuleMember -Function Set-BrokerGpoStatus

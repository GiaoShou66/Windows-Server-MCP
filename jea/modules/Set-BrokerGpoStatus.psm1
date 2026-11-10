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

    $deniedNames = @('Default Domain Policy', 'Default Domain Controllers Policy')
    $deniedGuids = @(
        '31b2f340-016d-11d2-945f-00c04fb984f9',
        '6ac1786c-016f-11d2-945f-00c04fb984f9'
    )

    if ($deniedNames -contains $GpoName) {
        throw "Modifications to Default Domain Policy and Default Domain Controllers Policy are denied by policy."
    }

    Import-Module GroupPolicy -ErrorAction Stop

    $gpo = Get-GPO -Name $GpoName -ErrorAction Stop
    $gpoGuid = $gpo.Id.ToString('D').ToLowerInvariant()

    if ($deniedGuids -contains $gpoGuid -or $deniedNames -contains $gpo.DisplayName) {
        throw "Modifications to Default Domain Policy and Default Domain Controllers Policy are denied by policy (protected GPO GUID: $($gpo.Id))."
    }

    $updated = Set-GPO -Name $GpoName -Status $Status -ErrorAction Stop
    [pscustomobject]@{
        DisplayName = $updated.DisplayName
        GpoStatus   = $updated.GpoStatus.ToString()
    }
}

Export-ModuleMember -Function Set-BrokerGpoStatus

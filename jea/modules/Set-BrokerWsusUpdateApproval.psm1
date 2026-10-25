#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Write: approve or decline a specific WSUS update by its UpdateId. Reversible.
#>
function Set-BrokerWsusUpdateApproval {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string] $UpdateId,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Approve', 'Decline')]
        [string] $Action
    )

    Import-Module UpdateServices -ErrorAction Stop

    $wsus = Get-WsusServer -ErrorAction Stop
    $update = $wsus.GetUpdate([guid]$UpdateId)
    if (-not $update) { throw "Update '$UpdateId' not found." }

    if ($Action -eq 'Approve') {
        $allComputers = $wsus.GetComputerTargetGroups() | Where-Object { $_.Name -eq 'All Computers' }
        $update.Approve('Install', $allComputers) | Out-Null
    }
    else {
        $update.Decline() | Out-Null
    }

    [pscustomobject]@{
        UpdateId   = $UpdateId
        Title      = $update.Title
        IsDeclined = $update.IsDeclined
    }
}

Export-ModuleMember -Function Set-BrokerWsusUpdateApproval

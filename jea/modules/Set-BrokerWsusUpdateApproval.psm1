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
        [ValidatePattern('^[A-Za-z0-9 _.-]{1,100}$')]
        [string] $TargetGroup,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Approve', 'Decline')]
        [string] $Action
    )

    # H4: Explicit target group required. Blanket approval to 'All Computers' is denied by policy.
    if ($TargetGroup -eq 'All Computers') {
        throw "Approval to target group 'All Computers' is denied by policy. An explicit scoped target group is required."
    }

    Import-Module UpdateServices -ErrorAction Stop

    $wsus = Get-WsusServer -ErrorAction Stop
    $update = $wsus.GetUpdate([guid]$UpdateId)
    if (-not $update) { throw "Update '$UpdateId' not found." }

    $target = $wsus.GetComputerTargetGroups() | Where-Object { $_.Name -eq $TargetGroup }
    if (-not $target) { throw "Target group '$TargetGroup' not found." }

    if ($Action -eq 'Approve') {
        $update.Approve('Install', $target) | Out-Null
    }
    else {
        $update.Decline() | Out-Null
    }

    [pscustomobject]@{
        UpdateId    = $UpdateId
        Title       = $update.Title
        TargetGroup = $TargetGroup
        IsDeclined  = $update.IsDeclined
    }
}

Export-ModuleMember -Function Set-BrokerWsusUpdateApproval

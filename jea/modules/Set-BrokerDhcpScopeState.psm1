#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Write: activate or deactivate a DHCP scope. Reversible. Does not delete the scope.
#>
function Set-BrokerDhcpScopeState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')]
        [string] $ScopeId,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Activate', 'Deactivate')]
        [string] $Action
    )

    Import-Module DhcpServer -ErrorAction Stop

    Get-DhcpServerv4Scope -ScopeId $ScopeId -ErrorAction Stop | Out-Null

    $state = if ($Action -eq 'Activate') { 'Active' } else { 'Inactive' }
    Set-DhcpServerv4Scope -ScopeId $ScopeId -State $state -ErrorAction Stop

    $updated = Get-DhcpServerv4Scope -ScopeId $ScopeId -ErrorAction Stop
    [pscustomobject]@{
        ScopeId = $updated.ScopeId.ToString()
        State   = $updated.State.ToString()
    }
}

Export-ModuleMember -Function Set-BrokerDhcpScopeState

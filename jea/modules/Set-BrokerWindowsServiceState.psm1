#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Write: start or stop a Windows service.
.NOTES
  Reversible — a stopped service can be started again and vice versa. A fixed denylist
  of critical infrastructure services is enforced here, inside the wrapper, so it cannot
  be bypassed by a caller-supplied ServiceName even though the broker-side allowlist only
  constrains the string SHAPE (alnum/dot/dash), not which specific service it names.
  No -Force on Stop-Service: a service with running dependents fails loudly rather than
  cascading an unexpected stop through other services.
#>
function Set-BrokerWindowsServiceState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9_.-]{1,80}$')]
        [string] $ServiceName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Start', 'Stop')]
        [string] $Action
    )

    $deniedServices = @(
        'NTDS', 'Netlogon', 'Kdc', 'W32Time', 'RpcSs', 'DcomLaunch',
        'WinRM', 'Winmgmt', 'McpBroker', 'LanmanServer', 'LanmanWorkstation', 'Dnscache'
    )
    if ($deniedServices -contains $ServiceName) {
        throw "Action on service '$ServiceName' is denied by policy (critical infrastructure service)."
    }

    Get-Service -Name $ServiceName -ErrorAction Stop | Out-Null

    if ($Action -eq 'Start') {
        Start-Service -Name $ServiceName -ErrorAction Stop
    }
    else {
        Stop-Service -Name $ServiceName -ErrorAction Stop
    }

    $updated = Get-Service -Name $ServiceName -ErrorAction Stop
    [pscustomobject]@{
        Name   = $updated.Name
        Status = $updated.Status.ToString()
    }
}

Export-ModuleMember -Function Set-BrokerWindowsServiceState

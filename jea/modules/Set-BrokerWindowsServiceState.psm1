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

    # Get-Service / Stop-Service accept a WILDCARD in -Name. A caller passing "NTD*" or "*"
    # would bypass any exact-match denylist entirely, so the name must be literal first.
    if ($ServiceName -match '[*?]') {
        throw "Service name '$ServiceName' is denied by policy (wildcards are not permitted)."
    }

    $deniedServices = @(
        # directory / authentication / time
        'NTDS', 'Netlogon', 'Kdc', 'W32Time', 'ADWS', 'DFSR',
        # RPC / COM / core boot
        'RpcSs', 'RpcEptMapper', 'DcomLaunch', 'BrokerInfrastructure', 'Power', 'PlugPlay',
        # remote management + the broker itself
        'WinRM', 'Winmgmt', 'McpBroker', 'TermService', 'SessionEnv', 'UmRdpService',
        # networking / name resolution
        'LanmanServer', 'LanmanWorkstation', 'Dnscache', 'Dhcp', 'Dns',
        # security + logging: reversible, but stopping them blinds the host
        'WinDefend', 'MpsSvc', 'EventLog', 'SecurityHealthService', 'Sense', 'WdNisSvc',
        'SamSs', 'LSM', 'CryptSvc', 'KeyIso', 'VaultSvc'
    )
    if ($deniedServices -contains $ServiceName) {
        throw "Action on service '$ServiceName' is denied by policy (critical infrastructure service)."
    }

    # Resolve first, then re-check the real short name: a friendly display name must not be
    # usable to address a denied service under a different string.
    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($deniedServices -contains $service.Name) {
        throw "Action on service '$($service.Name)' is denied by policy (critical infrastructure service)."
    }

    if ($Action -eq 'Start') {
        Start-Service -Name $service.Name -ErrorAction Stop
    }
    else {
        Stop-Service -Name $service.Name -ErrorAction Stop
    }

    $updated = Get-Service -Name $service.Name -ErrorAction Stop
    [pscustomobject]@{
        Name   = $updated.Name
        Status = $updated.Status.ToString()
    }
}

Export-ModuleMember -Function Set-BrokerWindowsServiceState

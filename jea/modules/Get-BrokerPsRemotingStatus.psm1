#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: return WinRM service state and configured listeners (PowerShell Remoting).
#>
function Get-BrokerPsRemotingStatus {
    [CmdletBinding()]
    param()

    $service = Get-Service -Name WinRM -ErrorAction Stop

    $listeners = Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate -ErrorAction SilentlyContinue |
        ForEach-Object {
            [pscustomobject]@{
                Transport = $_.Transport
                Address   = $_.Address
                Port      = $_.Port
                Enabled   = $_.Enabled
            }
        }

    [pscustomobject]@{
        ServiceStatus = $service.Status.ToString()
        StartType     = $service.StartType.ToString()
        Listeners     = $listeners
    }
}

Export-ModuleMember -Function Get-BrokerPsRemotingStatus

#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate AD Lightweight Directory Services instances on this host.
.NOTES
  AD LDS ships no dedicated enumeration cmdlet. Each configured instance registers as a
  Windows service named 'ADAM_<InstanceName>' — this is the standard, documented way to
  discover installed instances without binding to any specific instance's LDAP port.
#>
function Get-BrokerAdldsInstances {
    [CmdletBinding()]
    param()

    Get-Service -Name 'ADAM_*' -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{
            InstanceName = $_.Name -replace '^ADAM_', ''
            ServiceName  = $_.Name
            Status       = $_.Status.ToString()
        }
    }
}

Export-ModuleMember -Function Get-BrokerAdldsInstances

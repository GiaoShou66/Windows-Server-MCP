#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate services and their run state on this host.
#>
function Get-BrokerWindowsServices {
    [CmdletBinding()]
    param()

    Get-Service -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Name        = $_.Name
            DisplayName = $_.DisplayName
            Status      = $_.Status.ToString()
            StartType   = $_.StartType.ToString()
        }
    }
}

Export-ModuleMember -Function Get-BrokerWindowsServices

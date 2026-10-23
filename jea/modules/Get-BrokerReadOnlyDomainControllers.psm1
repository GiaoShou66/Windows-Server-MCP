#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate Read-Only Domain Controllers in the domain.
#>
function Get-BrokerReadOnlyDomainControllers {
    [CmdletBinding()]
    param()

    Import-Module ActiveDirectory -ErrorAction Stop

    Get-ADDomainController -Filter { IsReadOnly -eq $true } -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Name            = $_.Name
            Site            = $_.Site
            OperatingSystem = $_.OperatingSystem
            IPv4Address     = $_.IPv4Address
        }
    }
}

Export-ModuleMember -Function Get-BrokerReadOnlyDomainControllers

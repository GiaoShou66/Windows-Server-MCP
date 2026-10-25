#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate enabled Windows Firewall rules on this host.
.NOTES
  Bounded to enabled rules only, first 500 — the full rule set can number in the thousands.
#>
function Get-BrokerFirewallRules {
    [CmdletBinding()]
    param()

    Import-Module NetSecurity -ErrorAction Stop

    Get-NetFirewallRule -Enabled True -ErrorAction Stop | Select-Object -First 500 | ForEach-Object {
        [pscustomobject]@{
            Name        = $_.Name
            DisplayName = $_.DisplayName
            Direction   = $_.Direction.ToString()
            Action      = $_.Action.ToString()
            Profile     = $_.Profile.ToString()
        }
    }
}

Export-ModuleMember -Function Get-BrokerFirewallRules

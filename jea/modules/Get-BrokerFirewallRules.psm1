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

    $count = 0
    foreach ($rule in @(Get-NetFirewallRule -Enabled True -ErrorAction Stop)) {
        if ($null -eq $rule) { continue }
        if ($count -ge 500) { break }
        $count++
        [pscustomobject]@{
            Name        = $rule.Name
            DisplayName = $rule.DisplayName
            Direction   = $rule.Direction.ToString()
            Action      = $rule.Action.ToString()
            Profile     = $rule.Profile.ToString()
        }
    }
}

Export-ModuleMember -Function Get-BrokerFirewallRules

#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Write: enable or disable an existing Windows Firewall rule.
.NOTES
  Reversible — flips a boolean on an existing rule, never creates/deletes one.
  RuleName is the firewall rule's internal Name property (visible via list-firewall-rules
  alongside DisplayName), not the display name shown in the GUI.
#>
function Set-BrokerFirewallRuleEnabled {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9 _.-]{1,260}$')]
        [string] $RuleName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('true', 'false')]
        [string] $Enabled
    )

    Import-Module NetSecurity -ErrorAction Stop

    Get-NetFirewallRule -Name $RuleName -ErrorAction Stop | Out-Null

    if ($Enabled -eq 'true') {
        Enable-NetFirewallRule -Name $RuleName -ErrorAction Stop
    }
    else {
        Disable-NetFirewallRule -Name $RuleName -ErrorAction Stop
    }

    $updated = Get-NetFirewallRule -Name $RuleName -ErrorAction Stop
    [pscustomobject]@{
        Name    = $updated.Name
        Enabled = $updated.Enabled.ToString()
    }
}

Export-ModuleMember -Function Set-BrokerFirewallRuleEnabled

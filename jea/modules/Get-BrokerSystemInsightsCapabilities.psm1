#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate predictive analysis capabilities registered with System Insights.
#>
function Get-BrokerSystemInsightsCapabilities {
    [CmdletBinding()]
    param()

    Import-Module SystemInsights -ErrorAction Stop

    Get-InsightCapability -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Name    = $_.Name
            Enabled = $_.Enabled
        }
    }
}

Export-ModuleMember -Function Get-BrokerSystemInsightsCapabilities

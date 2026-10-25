#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: list Windows Server roles and features (Server Manager).
.NOTES
  Exposed through the McpBroker.ReadLocal JEA endpoint. InstalledOnly is
  ValidateSet-constrained to 'true'/'false' in the generated .psrc.
#>
function Get-BrokerWindowsFeatures {
    [CmdletBinding()]
    param(
        [ValidateSet('true', 'false')]
        [string] $InstalledOnly = 'false'
    )

    Import-Module ServerManager -ErrorAction Stop

    $features = Get-WindowsFeature -ErrorAction Stop
    if ($InstalledOnly -eq 'true') {
        $features = $features | Where-Object { $_.Installed }
    }

    $features | ForEach-Object {
        [pscustomobject]@{
            Name        = $_.Name
            DisplayName = $_.DisplayName
            Installed   = $_.Installed
            FeatureType = $_.FeatureType
        }
    }
}

Export-ModuleMember -Function Get-BrokerWindowsFeatures

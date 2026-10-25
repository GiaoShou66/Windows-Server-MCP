#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: list Group Policy Objects in the domain.
.NOTES
  Exposed through the McpBroker.ReadDirectory JEA endpoint (runs as the gMSA, so GPO
  enumeration carries real Kerberos auth against the domain). No parameters, so no
  injection surface. Output carries no secrets — GPO metadata only, not policy content.
  Get-GPO has no server-side result-size limit, so the result is capped client-side at
  500 — a large domain can have thousands of GPOs, and the broker's frame cap is 1MiB.
#>
function Get-BrokerGroupPolicies {
    [CmdletBinding()]
    param()

    Import-Module GroupPolicy -ErrorAction Stop

    Get-GPO -All -ErrorAction Stop | Select-Object -First 500 | ForEach-Object {
        [pscustomobject]@{
            DisplayName      = $_.DisplayName
            Id               = $_.Id
            GpoStatus        = $_.GpoStatus.ToString()
            CreationTime     = $_.CreationTime
            ModificationTime = $_.ModificationTime
        }
    }
}

Export-ModuleMember -Function Get-BrokerGroupPolicies

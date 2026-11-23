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

    $count = 0
    foreach ($gpo in @(Get-GPO -All -ErrorAction Stop)) {
        if ($null -eq $gpo) { continue }
        if ($count -ge 500) { break }
        $count++
        [pscustomobject]@{
            DisplayName      = $gpo.DisplayName
            Id               = $gpo.Id
            GpoStatus        = $gpo.GpoStatus.ToString()
            CreationTime     = $gpo.CreationTime
            ModificationTime = $gpo.ModificationTime
        }
    }
}

Export-ModuleMember -Function Get-BrokerGroupPolicies

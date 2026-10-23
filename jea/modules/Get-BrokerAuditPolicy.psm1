#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: return effective audit policy subcategory settings.
.NOTES
  auditpol.exe is allowlisted in the generated .psrc's VisibleExternalCommands for
  this tool only.
#>
function Get-BrokerAuditPolicy {
    [CmdletBinding()]
    param()

    $csv = & auditpol.exe /get /category:* /r
    if ($LASTEXITCODE -ne 0 -or -not $csv) {
        throw "auditpol returned no data (exit code $LASTEXITCODE)"
    }

    $csv | ConvertFrom-Csv | ForEach-Object {
        [pscustomobject]@{
            Subcategory    = $_.Subcategory
            AuditCondition = $_.'Inclusion Setting'
        }
    }
}

Export-ModuleMember -Function Get-BrokerAuditPolicy

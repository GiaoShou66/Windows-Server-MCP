#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate AD fine-grained password policies (PSOs).
#>
function Get-BrokerFineGrainedPasswordPolicies {
    [CmdletBinding()]
    param()

    Import-Module ActiveDirectory -ErrorAction Stop

    Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Name              = $_.Name
            Precedence        = $_.Precedence
            MinPasswordLength = $_.MinPasswordLength
            ComplexityEnabled = $_.ComplexityEnabled
            LockoutThreshold  = $_.LockoutThreshold
        }
    }
}

Export-ModuleMember -Function Get-BrokerFineGrainedPasswordPolicies

#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: return the effective AppLocker rule collections and enforcement mode.
#>
function Get-BrokerAppLockerPolicy {
    [CmdletBinding()]
    param()

    Import-Module AppLocker -ErrorAction Stop

    $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop

    $policy.RuleCollections | ForEach-Object {
        [pscustomobject]@{
            CollectionType  = $_.RuleCollectionType.ToString()
            EnforcementMode = $_.EnforcementMode.ToString()
            RuleCount       = $_.Count
        }
    }
}

Export-ModuleMember -Function Get-BrokerAppLockerPolicy

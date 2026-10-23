#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: return the default domain password and account lockout policy.
#>
function Get-BrokerDomainPasswordPolicy {
    [CmdletBinding()]
    param()

    Import-Module ActiveDirectory -ErrorAction Stop

    $p = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    [pscustomobject]@{
        MinPasswordLength           = $p.MinPasswordLength
        MinPasswordAge              = $p.MinPasswordAge.ToString()
        MaxPasswordAge              = $p.MaxPasswordAge.ToString()
        PasswordHistoryCount        = $p.PasswordHistoryCount
        ComplexityEnabled           = $p.ComplexityEnabled
        ReversibleEncryptionEnabled = $p.ReversibleEncryptionEnabled
        LockoutThreshold            = $p.LockoutThreshold
        LockoutDuration             = $p.LockoutDuration.ToString()
        LockoutObservationWindow    = $p.LockoutObservationWindow.ToString()
    }
}

Export-ModuleMember -Function Get-BrokerDomainPasswordPolicy

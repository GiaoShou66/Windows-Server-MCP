#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate enterprise Certificate Authorities published in AD (AD CS).
#>
function Get-BrokerCertificateAuthorities {
    [CmdletBinding()]
    param()

    Import-Module ADCSAdministration -ErrorAction Stop

    Get-CertificationAuthority -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Name          = $_.Name
            ComputerName  = $_.ComputerName
            IsRoot        = $_.IsRoot
            DisplayName   = $_.DisplayName
        }
    }
}

Export-ModuleMember -Function Get-BrokerCertificateAuthorities

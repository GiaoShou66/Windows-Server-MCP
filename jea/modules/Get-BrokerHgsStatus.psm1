#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: return the operation mode and configuration status of this Host Guardian Service.
#>
function Get-BrokerHgsStatus {
    [CmdletBinding()]
    param()

    Import-Module HgsServer -ErrorAction Stop

    $hgs = Get-HgsServer -ErrorAction Stop
    [pscustomobject]@{
        HgsServerOperationMode = $hgs.HgsServerOperationMode.ToString()
        AttestationUrl         = $hgs.AttestationUrl
        KeyProtectionUrl       = $hgs.KeyProtectionUrl
    }
}

Export-ModuleMember -Function Get-BrokerHgsStatus

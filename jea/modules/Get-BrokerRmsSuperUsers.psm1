#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate AD RMS super user group membership on this cluster.
#>
function Get-BrokerRmsSuperUsers {
    [CmdletBinding()]
    param()

    Import-Module ADRmsAdmin -ErrorAction Stop

    Get-RmsSuperUser -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Email   = $_.Email
            Enabled = $_.Enabled
        }
    }
}

Export-ModuleMember -Function Get-BrokerRmsSuperUsers

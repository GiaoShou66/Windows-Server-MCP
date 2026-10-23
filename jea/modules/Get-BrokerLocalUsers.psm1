#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate local (non-domain) user accounts on this host.
.NOTES
  SID is masked broker-side after return.
#>
function Get-BrokerLocalUsers {
    [CmdletBinding()]
    param()

    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop

    Get-LocalUser -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Name            = $_.Name
            Enabled         = $_.Enabled
            LastLogon       = $_.LastLogon
            PasswordExpires = $_.PasswordExpires
            SID             = $_.SID.Value
        }
    }
}

Export-ModuleMember -Function Get-BrokerLocalUsers

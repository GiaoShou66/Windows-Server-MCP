#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Write: enable or disable a domain user account. Reversible.
.NOTES
  krbtgt, the built-in Administrator, and the broker's own gMSA are denied inside the
  wrapper regardless of parameters — disabling any of these is catastrophic or
  self-defeating (the gMSA is the identity this very JEA session runs as).
#>
function Set-BrokerAdUserEnabled {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[a-zA-Z0-9._-]{1,64}$')]
        [string] $SamAccountName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('true', 'false')]
        [string] $Enabled
    )

    $deniedUsers = @('krbtgt', 'Administrator', 'McpBrokerSvc$')
    if ($deniedUsers -contains $SamAccountName) {
        throw "Action on AD user '$SamAccountName' is denied by policy (critical account)."
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    Get-ADUser -Identity $SamAccountName -ErrorAction Stop | Out-Null

    if ($Enabled -eq 'true') {
        Enable-ADAccount -Identity $SamAccountName -ErrorAction Stop
    }
    else {
        Disable-ADAccount -Identity $SamAccountName -ErrorAction Stop
    }

    $updated = Get-ADUser -Identity $SamAccountName -Properties Enabled -ErrorAction Stop
    [pscustomobject]@{
        SamAccountName = $updated.SamAccountName
        Enabled        = $updated.Enabled
    }
}

Export-ModuleMember -Function Set-BrokerAdUserEnabled

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

    # Resolve by the explicit -SamAccountName form. -Identity also accepts distinguished
    # names, objectGUIDs and SIDs, so a caller could pass "S-1-5-21-...-500" (the built-in
    # Administrator's well-known RID) and skip the name-based denylist below entirely.
    # Binding to -SamAccountName makes the accepted identity shape unambiguous.
    $deniedUsers = @('krbtgt', 'Administrator', 'McpBrokerSvc$', 'McpBrokerReadSvc$', 'McpBrokerWriteSvc$')
    if ($deniedUsers -contains $SamAccountName) {
        throw "Action on AD user '$SamAccountName' is denied by policy (critical account)."
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    $account = Get-ADUser -SamAccountName $SamAccountName -Properties SamAccountName, ObjectGuid, SID -ErrorAction Stop

    # Belt and braces: reject anything resolving to a privileged well-known RID
    # (-500 built-in Administrator, -502 krbtgt) even if a name lookup slipped through.
    if ($account.SID.Value -match '-500$' -or $account.SID.Value -match '-502$') {
        throw "Action on AD user '$SamAccountName' is denied by policy (privileged RID)."
    }

    if ($Enabled -eq 'true') {
        Enable-ADAccount -Identity $account.ObjectGuid -ErrorAction Stop
    }
    else {
        Disable-ADAccount -Identity $account.ObjectGuid -ErrorAction Stop
    }

    $updated = Get-ADUser -Identity $account.ObjectGuid -Properties Enabled -ErrorAction Stop
    [pscustomobject]@{
        SamAccountName = $updated.SamAccountName
        Enabled        = $updated.Enabled
    }
}

Export-ModuleMember -Function Set-BrokerAdUserEnabled

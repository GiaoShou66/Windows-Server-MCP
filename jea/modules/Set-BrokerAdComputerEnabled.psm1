#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Write: enable or disable a domain computer account. Reversible.
.NOTES
  Domain controllers are denied inside the wrapper, checked live against the current
  DC list (not a static name list) — disabling a DC's computer account is catastrophic.
#>
function Set-BrokerAdComputerEnabled {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[a-zA-Z0-9._-]{1,64}$')]
        [string] $ComputerName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('true', 'false')]
        [string] $Enabled
    )

    Import-Module ActiveDirectory -ErrorAction Stop

    # -Identity accepts DNs, GUIDs and SIDs as well as names; bind to the explicit name
    # form so a caller cannot address a domain controller by its SID and skip the check.
    $computer = Get-ADComputer -Filter 'Name -eq $ComputerName' `
        -Properties Enabled, ObjectGuid, SID -ErrorAction Stop | Select-Object -First 1
    if (-not $computer) {
        throw "Computer '$ComputerName' not found."
    }

    # A domain controller's machine account carries SERVER_TRUST_ACCOUNT (0x20000000) in
    # its RID, and lives under CN=Domain Controllers. Check the SID bit (authoritative),
    # the DN, and the live DC list (which can be stale), so no single stale source wins.
    $rid = [int64]($computer.SID.Value -replace '^.*-', '')
    $isDcSid = ($rid -band 0x20000000) -ne 0
    $inDcContainer = $computer.DistinguishedName -match 'CN=Domain Controllers,'
    $dcNames = @((Get-ADDomainController -Filter * -ErrorAction Stop).Name)
    if ($isDcSid -or $inDcContainer -or ($dcNames -contains $computer.Name)) {
        throw "Action on computer '$ComputerName' is denied by policy (domain controller)."
    }

    if ($Enabled -eq 'true') {
        Enable-ADAccount -Identity $computer.ObjectGuid -ErrorAction Stop
    }
    else {
        Disable-ADAccount -Identity $computer.ObjectGuid -ErrorAction Stop
    }

    $updated = Get-ADComputer -Identity $computer.ObjectGuid -Properties Enabled -ErrorAction Stop
    [pscustomobject]@{
        Name    = $updated.Name
        Enabled = $updated.Enabled
    }
}

Export-ModuleMember -Function Set-BrokerAdComputerEnabled

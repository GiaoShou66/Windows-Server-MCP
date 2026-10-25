#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: return a limited AD user profile by sAMAccountName.
.NOTES
  Exposed through the McpBroker.ReadDirectory JEA endpoint (runs as the gMSA, so the
  AD query carries real Kerberos auth). SamAccountName is ValidatePattern-constrained
  in the generated .psrc, so injection-shaped input never reaches Get-ADUser.
  Sensitive fields (objectSid, distinguishedName) are masked broker-side after return.
#>
function Get-BrokerAdUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[a-zA-Z0-9._-]{1,64}$')]
        [string] $SamAccountName
    )

    Import-Module ActiveDirectory -ErrorAction Stop

    $u = Get-ADUser -Identity $SamAccountName -Properties `
        DisplayName, Enabled, LastLogonDate, Department, Title, objectSid, distinguishedName `
        -ErrorAction Stop

    [pscustomobject]@{
        SamAccountName    = $u.SamAccountName
        DisplayName       = $u.DisplayName
        Enabled           = $u.Enabled
        LastLogonDate     = $u.LastLogonDate
        Department        = $u.Department
        Title             = $u.Title
        objectSid         = $u.objectSid.Value
        distinguishedName = $u.distinguishedName
    }
}

Export-ModuleMember -Function Get-BrokerAdUser

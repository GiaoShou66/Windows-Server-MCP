#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate AD computer accounts.
.NOTES
  Exposed through the McpBroker.ReadDirectory JEA endpoint (gMSA identity, real Kerberos).
  objectSid is masked broker-side after return. ResultSetSize bounds the query
  server-side — an unbounded -Filter * against a large domain (tens of thousands of
  computer objects) risks exceeding the broker's 1MiB frame cap and loading the DC
  for no benefit; this stops the AD query itself from over-fetching.
#>
function Get-BrokerAdComputers {
    [CmdletBinding()]
    param()

    Import-Module ActiveDirectory -ErrorAction Stop

    Get-ADComputer -Filter * -ResultSetSize 1000 -Properties OperatingSystem, LastLogonDate, Enabled, objectSid -ErrorAction Stop |
        ForEach-Object {
            [pscustomobject]@{
                Name            = $_.Name
                OperatingSystem = $_.OperatingSystem
                LastLogonDate   = $_.LastLogonDate
                Enabled         = $_.Enabled
                objectSid       = $_.objectSid.Value
            }
        }
}

Export-ModuleMember -Function Get-BrokerAdComputers

#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: list IIS sites on this host.
.NOTES
  Exposed through the McpBroker.ReadLocal JEA endpoint. Requires the Web-Scripting-Tools
  feature (WebAdministration module) to be installed on the IIS host. Bindings are
  flattened to plain strings since BindingCollection objects don't serialize cleanly.
#>
function Get-BrokerIisSites {
    [CmdletBinding()]
    param()

    Import-Module WebAdministration -ErrorAction Stop

    Get-Website -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Name            = $_.Name
            Id              = $_.Id
            State           = $_.State.ToString()
            PhysicalPath    = $_.PhysicalPath
            Bindings        = ($_.Bindings.Collection | ForEach-Object { $_.bindingInformation }) -join ';'
            ApplicationPool = $_.applicationPool
        }
    }
}

Export-ModuleMember -Function Get-BrokerIisSites

#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate IPv4 scopes on this DHCP server.
#>
function Get-BrokerDhcpScopes {
    [CmdletBinding()]
    param()

    Import-Module DhcpServer -ErrorAction Stop

    Get-DhcpServerv4Scope -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            ScopeId     = $_.ScopeId.ToString()
            Name        = $_.Name
            State       = $_.State.ToString()
            StartRange  = $_.StartRange.ToString()
            EndRange    = $_.EndRange.ToString()
        }
    }
}

Export-ModuleMember -Function Get-BrokerDhcpScopes

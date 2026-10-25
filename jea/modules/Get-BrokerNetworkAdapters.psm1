#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate network adapters and their IPv4 configuration on this host.
#>
function Get-BrokerNetworkAdapters {
    [CmdletBinding()]
    param()

    Import-Module NetAdapter -ErrorAction Stop
    Import-Module NetTCPIP -ErrorAction Stop

    Get-NetAdapter -ErrorAction Stop | ForEach-Object {
        $adapter = $_
        $ip = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty IPAddress

        [pscustomobject]@{
            Name        = $adapter.Name
            Status      = $adapter.Status.ToString()
            LinkSpeed   = $adapter.LinkSpeed
            MacAddress  = $adapter.MacAddress
            IPv4Address = $ip
        }
    }
}

Export-ModuleMember -Function Get-BrokerNetworkAdapters

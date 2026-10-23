#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate RemoteApp/session collections (Remote Desktop Services).
#>
function Get-BrokerRdsCollections {
    [CmdletBinding()]
    param()

    Import-Module RemoteDesktop -ErrorAction Stop

    Get-RDSessionCollection -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            CollectionName = $_.CollectionName
            CollectionType = $_.CollectionType.ToString()
            Size           = $_.Size
        }
    }
}

Export-ModuleMember -Function Get-BrokerRdsCollections

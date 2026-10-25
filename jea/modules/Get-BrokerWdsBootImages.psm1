#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate boot images on this Windows Deployment Services server.
#>
function Get-BrokerWdsBootImages {
    [CmdletBinding()]
    param()

    Import-Module WDS -ErrorAction Stop

    Get-WdsBootImage -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            ImageName    = $_.ImageName
            Architecture = $_.Architecture.ToString()
            FileName     = $_.FileName
        }
    }
}

Export-ModuleMember -Function Get-BrokerWdsBootImages

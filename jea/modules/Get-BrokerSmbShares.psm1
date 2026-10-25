#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate SMB file shares on this host (File and Storage Services).
.NOTES
  Bounded to 500 — a large file server can host many shares.
#>
function Get-BrokerSmbShares {
    [CmdletBinding()]
    param()

    Import-Module SmbShare -ErrorAction Stop

    Get-SmbShare -ErrorAction Stop | Select-Object -First 500 | ForEach-Object {
        [pscustomobject]@{
            Name        = $_.Name
            Path        = $_.Path
            Description = $_.Description
            ShareType   = $_.ShareType.ToString()
        }
    }
}

Export-ModuleMember -Function Get-BrokerSmbShares

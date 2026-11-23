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

    $count = 0
    foreach ($share in @(Get-SmbShare -ErrorAction Stop)) {
        if ($null -eq $share) { continue }
        if ($count -ge 500) { break }
        $count++
        [pscustomobject]@{
            Name        = $share.Name
            Path        = $share.Path
            Description = $share.Description
            ShareType   = $share.ShareType.ToString()
        }
    }
}

Export-ModuleMember -Function Get-BrokerSmbShares

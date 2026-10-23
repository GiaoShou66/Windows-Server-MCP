#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate Storage Migration Service jobs configured on this host.
#>
function Get-BrokerStorageMigrationJobs {
    [CmdletBinding()]
    param()

    Import-Module StorageMigrationService -ErrorAction Stop

    Get-SmsJob -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Name  = $_.Name
            State = $_.State.ToString()
        }
    }
}

Export-ModuleMember -Function Get-BrokerStorageMigrationJobs

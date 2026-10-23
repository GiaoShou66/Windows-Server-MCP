#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate FTP sites on this host (IIS 10.0 FTP Server role).
#>
function Get-BrokerFtpSites {
    [CmdletBinding()]
    param()

    Import-Module WebAdministration -ErrorAction Stop

    Get-Website -ErrorAction Stop | Where-Object {
        $_.Bindings.Collection | Where-Object { $_.protocol -eq 'ftp' }
    } | ForEach-Object {
        $ftpBindings = $_.Bindings.Collection | Where-Object { $_.protocol -eq 'ftp' } |
            ForEach-Object { $_.bindingInformation }

        [pscustomobject]@{
            Name         = $_.Name
            State        = $_.State.ToString()
            PhysicalPath = $_.PhysicalPath
            FtpBindings  = ($ftpBindings -join ';')
        }
    }
}

Export-ModuleMember -Function Get-BrokerFtpSites

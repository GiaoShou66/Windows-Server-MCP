#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate shared printers on this print server (Print and Document Services).
.NOTES
  Bounded to 500 — a large print server can host hundreds of printer queues.
#>
function Get-BrokerPrinters {
    [CmdletBinding()]
    param()

    Import-Module PrintManagement -ErrorAction Stop

    Get-Printer -ErrorAction Stop | Select-Object -First 500 | ForEach-Object {
        [pscustomobject]@{
            Name          = $_.Name
            DriverName    = $_.DriverName
            PortName      = $_.PortName
            Shared        = $_.Shared
            PrinterStatus = $_.PrinterStatus.ToString()
        }
    }
}

Export-ModuleMember -Function Get-BrokerPrinters

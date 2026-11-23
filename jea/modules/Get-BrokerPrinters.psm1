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

    $count = 0
    foreach ($printer in @(Get-Printer -ErrorAction Stop)) {
        if ($null -eq $printer) { continue }
        if ($count -ge 500) { break }
        $count++
        [pscustomobject]@{
            Name          = $printer.Name
            DriverName    = $printer.DriverName
            PortName      = $printer.PortName
            Shared        = $printer.Shared
            PrinterStatus = $printer.PrinterStatus.ToString()
        }
    }
}

Export-ModuleMember -Function Get-BrokerPrinters

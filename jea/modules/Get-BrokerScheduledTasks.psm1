#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate scheduled tasks and their state on this host.
#>
function Get-BrokerScheduledTasks {
    [CmdletBinding()]
    param()

    Import-Module ScheduledTasks -ErrorAction Stop

    Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            TaskName = $_.TaskName
            TaskPath = $_.TaskPath
            State    = $_.State.ToString()
            Author   = $_.Author
        }
    }
}

Export-ModuleMember -Function Get-BrokerScheduledTasks

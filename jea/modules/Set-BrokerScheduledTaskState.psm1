#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Write: enable or disable an existing scheduled task.
.NOTES
  Reversible — flips a boolean state on an existing task, never creates/deletes one.
  TaskPath/TaskName are ValidatePattern-constrained in the generated .psrc. This is a
  write-tier tool: the broker requires human elicitation approval before this runs.
#>
function Set-BrokerScheduledTaskState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^\\[\\A-Za-z0-9 _.-]*\\$')]
        [string] $TaskPath,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9 _.-]{1,260}$')]
        [string] $TaskName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('true', 'false')]
        [string] $Enabled
    )

    Import-Module ScheduledTasks -ErrorAction Stop

    # Confirm the task exists before attempting to change it — fail with a clear
    # error rather than letting Enable/Disable-ScheduledTask surface a vague one.
    Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop | Out-Null

    if ($Enabled -eq 'true') {
        Enable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop | Out-Null
    }
    else {
        Disable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop | Out-Null
    }

    $updated = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop
    [pscustomobject]@{
        TaskPath = $updated.TaskPath
        TaskName = $updated.TaskName
        State    = $updated.State.ToString()
    }
}

Export-ModuleMember -Function Set-BrokerScheduledTaskState

#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: return the PowerShell execution policy at every scope.
#>
function Get-BrokerExecutionPolicy {
    [CmdletBinding()]
    param()

    Get-ExecutionPolicy -List -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Scope           = $_.Scope.ToString()
            ExecutionPolicy = $_.ExecutionPolicy.ToString()
        }
    }
}

Export-ModuleMember -Function Get-BrokerExecutionPolicy

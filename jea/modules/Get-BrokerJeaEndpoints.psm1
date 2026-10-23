#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: list registered JEA session configurations on this host.
.NOTES
  Exposed through the McpBroker.ReadLocal JEA endpoint as the only visible cmdlet.
  Returns a projected, non-sensitive view (name, run-as identity kind, language mode).
#>
function Get-BrokerJeaEndpoints {
    [CmdletBinding()]
    param()

    Get-PSSessionConfiguration -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'McpBroker.*' } |
        ForEach-Object {
            [pscustomobject]@{
                Name         = $_.Name
                RunAsUser    = $_.RunAsUser
                Permission   = $_.Permission
                LanguageMode = $_.LanguageMode
            }
        }
}

Export-ModuleMember -Function Get-BrokerJeaEndpoints

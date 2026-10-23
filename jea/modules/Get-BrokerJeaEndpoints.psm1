#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: list registered JEA session configurations on this host.
.NOTES
  Exposed through the McpBroker.ReadLocal JEA endpoint as the only visible cmdlet.
  Returns a projected view: Name, RunAsUser, Permission and LanguageMode. RunAsUser and
  Permission name security principals (who may call each endpoint and as whom it runs), so the
  output is internal security configuration, not public metadata.
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

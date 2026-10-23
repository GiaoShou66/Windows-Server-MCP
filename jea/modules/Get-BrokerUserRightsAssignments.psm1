#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: enumerate local security policy user rights assignments.
.NOTES
  secedit.exe is allowlisted in the generated .psrc's VisibleExternalCommands for
  this tool only.
#>
function Get-BrokerUserRightsAssignments {
    [CmdletBinding()]
    param()

    $tmp = Join-Path $env:TEMP "mcpbroker-userrights-$([guid]::NewGuid().ToString('N')).cfg"
    try {
        & secedit.exe /export /cfg $tmp /areas USER_RIGHTS | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $tmp)) {
            throw "secedit export failed (exit code $LASTEXITCODE)"
        }

        $inSection = $false
        Get-Content -LiteralPath $tmp | ForEach-Object {
            if ($_ -match '^\[Privilege Rights\]') { $inSection = $true; return }
            if ($inSection -and $_ -match '^\[') { $inSection = $false; return }
            if ($inSection -and $_ -match '^(Se\w+)\s*=\s*(.*)$') {
                [pscustomobject]@{
                    Privilege  = $Matches[1]
                    AssignedTo = $Matches[2]
                }
            }
        }
    }
    finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

Export-ModuleMember -Function Get-BrokerUserRightsAssignments

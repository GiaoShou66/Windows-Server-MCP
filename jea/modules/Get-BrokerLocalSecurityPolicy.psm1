#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Read-only: return local password and account lockout policy settings.
.NOTES
  There is no native cmdlet for local security policy; secedit.exe's SECURITYPOLICY
  export is the standard, documented mechanism. secedit.exe is allowlisted in the
  generated .psrc's VisibleExternalCommands for this tool only.
#>
function Get-BrokerLocalSecurityPolicy {
    [CmdletBinding()]
    param()

    $tmp = Join-Path $env:TEMP "mcpbroker-secpol-$([guid]::NewGuid().ToString('N')).cfg"
    try {
        & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $tmp)) {
            throw "secedit export failed (exit code $LASTEXITCODE)"
        }

        $values = @{}
        foreach ($line in (Get-Content -LiteralPath $tmp)) {
            if ($line -match '^\s*([A-Za-z]+)\s*=\s*(.+?)\s*$') {
                $values[$Matches[1]] = $Matches[2]
            }
        }

        [pscustomobject]@{
            MinimumPasswordAge    = $values['MinimumPasswordAge']
            MaximumPasswordAge    = $values['MaximumPasswordAge']
            MinimumPasswordLength = $values['MinimumPasswordLength']
            PasswordComplexity    = $values['PasswordComplexity']
            PasswordHistorySize   = $values['PasswordHistorySize']
            LockoutBadCount       = $values['LockoutBadCount']
            ResetLockoutCount     = $values['ResetLockoutCount']
            LockoutDuration       = $values['LockoutDuration']
        }
    }
    finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

Export-ModuleMember -Function Get-BrokerLocalSecurityPolicy

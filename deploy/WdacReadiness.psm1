#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  Decides whether an audited WDAC policy may be promoted to enforcement. Pure logic: every
  fact it needs is passed in, so it can be unit-tested without a Windows host.
.DESCRIPTION
  Returns an object with Ready (bool) and Reasons (string[]). Ready is true ONLY when there are no
  reasons. Every override switch is explicit, and a caller is expected to record which overrides
  were used.

  What this can and cannot establish. It checks that an Audit-mode artifact exists, is unchanged
  since it was built, has been in place for a minimum period, produced no unreviewed
  "would have been blocked" events, and that the Code Integrity log shows the policy being loaded.
  It cannot prove the audit period exercised every workload the server runs, and it cannot prove
  the server will boot or run its services under enforcement. The log queries behind the counts are
  best effort and have not been validated on a Windows host by this repository's tests.
#>
function Test-WdacEnforcementReadiness {
    [CmdletBinding()]
    param(
        # Parsed audit-state.json written when the Audit policy was built; $null when absent.
        [Parameter(Mandatory = $true)] [AllowNull()] [object] $State,

        # SHA-256 of the saved audit policy XML as it is on disk right now.
        [Parameter(Mandatory = $true)] [string] $CurrentAuditXmlHash,

        [Parameter(Mandatory = $true)] [datetime] $NowUtc,

        # Count of Code Integrity "audit block" (3076) events since the audit began; -1 = log unreadable.
        [Parameter(Mandatory = $true)] [int] $AuditEventCount,

        # Count of events showing THIS policy being loaded since the audit began; -1 = log unreadable.
        [Parameter(Mandatory = $true)] [int] $PolicyLoadedEventCount,

        [ValidateRange(1, 365)] [int] $MinAuditDays = 7,

        [string] $ConfirmationText = '',
        [Parameter(Mandatory = $true)] [string] $ExpectedConfirmationText,

        [switch] $AcceptShortAudit,
        [switch] $AcceptAuditFindings,
        [switch] $AssumeAuditPolicyActive
    )

    $reasons = New-Object System.Collections.Generic.List[string]

    if ($null -eq $State) {
        $reasons.Add('No audit state found. Build the policy in Audit mode, deploy it, and let it run first.')
    }
    else {
        if ($State.Mode -ne 'Audit') {
            $reasons.Add("The recorded state is '$($State.Mode)', not 'Audit'.")
        }

        if ([string]::IsNullOrWhiteSpace([string] $State.AuditXmlHash) -or
            -not [string]::Equals([string] $State.AuditXmlHash, $CurrentAuditXmlHash, [StringComparison]::OrdinalIgnoreCase)) {
            $reasons.Add('The saved audit policy differs from the one the audit period was recorded for. Re-run Audit mode and audit again.')
        }

        $started = $null
        try {
            # Explicit UTC parse; Parse/try-catch rather than TryParse because [ref] overload
            # resolution for TryParse is unreliable across PowerShell versions.
            $started = [datetime]::Parse([string] $State.AuditStartedUtc, [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
        }
        catch {
            $started = $null
        }

        if ($null -eq $started) {
            $reasons.Add('The audit start time in the state file is missing or unreadable.')
        }
        elseif ($started -gt $NowUtc) {
            $reasons.Add('The audit start time is in the future; the state file or the clock is wrong.')
        }
        elseif (($NowUtc - $started).TotalDays -lt $MinAuditDays -and -not $AcceptShortAudit) {
            $days = [math]::Round(($NowUtc - $started).TotalDays, 1)
            $reasons.Add("The policy has been auditing for $days day(s); at least $MinAuditDays are required (override: -AcceptShortAudit).")
        }
    }

    if ($AuditEventCount -lt 0) {
        $reasons.Add('The Code Integrity event log could not be read, so audit findings cannot be assessed.')
    }
    elseif ($AuditEventCount -gt 0 -and -not $AcceptAuditFindings) {
        $reasons.Add("$AuditEventCount file(s) would have been blocked during the audit. Review them, add rules or accept the findings (override: -AcceptAuditFindings).")
    }

    if ($PolicyLoadedEventCount -le 0 -and -not $AssumeAuditPolicyActive) {
        $reasons.Add('There is no evidence in the event log that the audit policy was loaded, so an empty finding list proves nothing (override: -AssumeAuditPolicyActive).')
    }

    if (-not [string]::Equals($ConfirmationText, $ExpectedConfirmationText, [StringComparison]::Ordinal)) {
        $reasons.Add("Typed confirmation missing or wrong. Pass -ConfirmEnforcement '$ExpectedConfirmationText'.")
    }

    [pscustomobject]@{
        Ready   = ($reasons.Count -eq 0)
        Reasons = $reasons.ToArray()
    }
}

Export-ModuleMember -Function Test-WdacEnforcementReadiness

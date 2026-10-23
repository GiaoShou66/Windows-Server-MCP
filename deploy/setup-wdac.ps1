#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
  Builds a WDAC code-integrity policy that permits the Windows base set plus signed MCP broker
  binaries/modules in one directory. Audit first; enforcement is a separate, gated step.
.DESCRIPTION
  This script BUILDS policy files. It does not deploy them: it prints the CiTool command, and the
  operator runs it after reviewing the output.

  Policy shape. The MCP rules are MERGED into a Windows base policy. A policy generated from the MCP
  directory alone would allow nothing else and, once enforced, would block Windows itself.

  Audit mode (default). Scans ServerPath, merges with the base policy, sets the Audit option and
  saves the exact policy as audit.xml with an audit-state.json (start time, policy hash).
  Re-running Audit mode builds a NEW policy and restarts the audit period.

  Enforced mode. Does not rebuild anything. It promotes the saved audit.xml (same policy id, rules
  identical to what was audited) after Test-WdacEnforcementReadiness passes:
    - an audit state exists, the audit.xml is unchanged since, and it has run MinAuditDays
    - no unreviewed "would have been blocked" events, and the log shows the policy loaded
    - a typed confirmation, e.g.  -ConfirmEnforcement 'ENFORCE <COMPUTERNAME>'
  The enforced policy also gets "Boot Audit on Failure" so a boot-critical driver the audit missed
  degrades to audit instead of leaving the server unbootable.

  NOT verified by this repository's tests: that the Code Integrity event queries return what is
  expected, that a given policy is safe for a given server, or that rollback works on a given
  configuration. The readiness decision logic IS unit-tested. Rehearse on a non-production
  server with out-of-band console access first. See docs/security-hardening.md (WDAC).
.PARAMETER ServerPath
  Directory where signed MCP server binaries/modules live, e.g. 'C:\McpBroker\jea'.
.PARAMETER Mode
  'Audit' (default) or 'Enforced'.
.PARAMETER BasePolicyXml
  Windows base policy XML. Required to exist; there is deliberately no "build without a base" path.
.PARAMETER MinAuditDays
  Minimum days the audit policy must have been in place before enforcement (default 7).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $ServerPath,
    [ValidateSet('Audit', 'Enforced')] [string] $Mode = 'Audit',
    [string] $PolicyDir = 'C:\McpBroker\wdac',
    [string] $BasePolicyXml = (Join-Path $env:windir 'schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml'),
    [ValidateRange(1, 365)] [int] $MinAuditDays = 7,
    [string] $ConfirmEnforcement = '',
    [switch] $AcceptShortAudit,
    [switch] $AcceptAuditFindings,
    [switch] $AssumeAuditPolicyActive
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'WdacReadiness.psm1') -Force

function Assert-AdminOnlyDirectory {
    param([Parameter(Mandatory = $true)] [string] $Path)

    $broad = @('Everyone', 'NT AUTHORITY\Authenticated Users', 'BUILTIN\Users')
    $writeBits = [System.Security.AccessControl.FileSystemRights]::Write -bor
                 [System.Security.AccessControl.FileSystemRights]::Modify -bor
                 [System.Security.AccessControl.FileSystemRights]::FullControl
    foreach ($rule in (Get-Acl -LiteralPath $Path).Access) {
        if ($rule.AccessControlType -eq 'Allow' -and ($broad -contains $rule.IdentityReference.Value) -and
            (($rule.FileSystemRights -band $writeBits) -ne 0)) {
            throw "Refusing to keep WDAC policy state in '$Path': '$($rule.IdentityReference.Value)' can modify it."
        }
    }
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)] [string] $Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Get-CiEventCount {
    param(
        [Parameter(Mandatory = $true)] [int] $Id,
        [Parameter(Mandatory = $true)] [datetime] $SinceUtc,
        [string] $MessageContains = ''
    )
    # -1 means "could not be determined"; the readiness check treats that as NOT ready.
    try {
        $events = @(Get-WinEvent -FilterHashtable @{
                LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
                Id        = $Id
                StartTime = $SinceUtc.ToLocalTime()
            } -ErrorAction Stop)
        if ($MessageContains) { $events = @($events | Where-Object { $_.Message -like "*$MessageContains*" }) }
        return $events.Count
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return 0 }
        Write-Warning "Could not read event $Id from the Code Integrity log: $($_.Exception.Message)"
        return -1
    }
}

New-Item -ItemType Directory -Path $PolicyDir -Force | Out-Null
Assert-AdminOnlyDirectory -Path $PolicyDir

$auditXml  = Join-Path $PolicyDir 'audit.xml'
$auditCip  = Join-Path $PolicyDir 'audit.cip'
$enforcedXml = Join-Path $PolicyDir 'enforced.xml'
$enforcedCip = Join-Path $PolicyDir 'enforced.cip'
$stateFile = Join-Path $PolicyDir 'audit-state.json'

if ($Mode -eq 'Audit') {
    if (-not (Test-Path -LiteralPath $ServerPath -PathType Container)) { throw "ServerPath '$ServerPath' not found." }
    if (-not (Test-Path -LiteralPath $BasePolicyXml -PathType Leaf)) {
        throw "Base policy '$BasePolicyXml' not found. Refusing to build a policy from the MCP directory alone: enforced, it would block Windows itself."
    }

    $scanned = Join-Path $PolicyDir 'mcp-rules.xml'
    $merged  = Join-Path $PolicyDir 'merged.xml'

    # PcaCertificate level keys on the signing CA; with FilePathRules it scopes the allowed MCP code.
    New-CIPolicy -FilePath $scanned -ScanPath $ServerPath -Level PcaCertificate `
        -FilePathRules -UserPEs -Fallback Hash -ErrorAction Stop
    Merge-CIPolicy -PolicyPaths $BasePolicyXml, $scanned -OutputFilePath $merged -ErrorAction Stop

    Copy-Item -LiteralPath $merged -Destination $auditXml -Force
    Set-RuleOption -FilePath $auditXml -Option 3          # Audit Mode: log, do not block
    ConvertFrom-CIPolicy -XmlFilePath $auditXml -BinaryFilePath $auditCip

    $policyId = ([xml](Get-Content -LiteralPath $auditXml -Raw)).SiPolicy.PolicyID
    [pscustomobject]@{
        Mode            = 'Audit'
        AuditStartedUtc = (Get-Date).ToUniversalTime().ToString('o')
        AuditXmlHash    = Get-FileSha256 -Path $auditXml
        PolicyId        = $policyId
        BasePolicy      = $BasePolicyXml
        BasePolicyHash  = Get-FileSha256 -Path $BasePolicyXml
        ServerPath      = $ServerPath
    } | ConvertTo-Json | Set-Content -LiteralPath $stateFile -Encoding UTF8

    Write-Host "Audit policy built: $auditCip (policy id $policyId)"
    Write-Host "Nothing has been deployed. Review, then deploy with:  CiTool --update-policy `"$auditCip`""
    Write-Host "Let it run for at least $MinAuditDays day(s) under realistic load, review"
    Write-Host "Microsoft-Windows-CodeIntegrity/Operational (event 3076), then re-run with -Mode Enforced."
    return
}

# ---- Enforced: promote the audited artifact after the readiness gate --------------------------
$state = $null
if (Test-Path -LiteralPath $stateFile) { $state = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json }
if (-not (Test-Path -LiteralPath $auditXml)) { $state = $null }

$auditHash = if ($state) { Get-FileSha256 -Path $auditXml } else { '' }
$started = $null
if ($state) {
    try {
        $started = [datetime]::Parse([string] $state.AuditStartedUtc, [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
    }
    catch {
        $started = $null
    }
}

if ($null -ne $started) {
    $blocked = Get-CiEventCount -Id 3076 -SinceUtc $started
    $loaded  = Get-CiEventCount -Id 3099 -SinceUtc $started -MessageContains ([string] $state.PolicyId)
}
else {
    $blocked = -1
    $loaded  = -1
}

$verdict = Test-WdacEnforcementReadiness `
    -State $state -CurrentAuditXmlHash $auditHash -NowUtc (Get-Date).ToUniversalTime() `
    -AuditEventCount $blocked -PolicyLoadedEventCount $loaded -MinAuditDays $MinAuditDays `
    -ConfirmationText $ConfirmEnforcement -ExpectedConfirmationText "ENFORCE $env:COMPUTERNAME" `
    -AcceptShortAudit:$AcceptShortAudit -AcceptAuditFindings:$AcceptAuditFindings `
    -AssumeAuditPolicyActive:$AssumeAuditPolicyActive

if (-not $verdict.Ready) {
    Write-Host 'WDAC policy is NOT ready for enforcement:' -ForegroundColor Red
    $verdict.Reasons | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    throw 'Enforcement refused. Nothing was built.'
}

$overrides = @()
if ($AcceptShortAudit)         { $overrides += 'AcceptShortAudit' }
if ($AcceptAuditFindings)      { $overrides += 'AcceptAuditFindings' }
if ($AssumeAuditPolicyActive)  { $overrides += 'AssumeAuditPolicyActive' }

# Same rules, same policy id: remove only the audit option. Boot Audit on Failure is the safety net.
Copy-Item -LiteralPath $auditXml -Destination $enforcedXml -Force
Set-RuleOption -FilePath $enforcedXml -Option 3 -Delete
Set-RuleOption -FilePath $enforcedXml -Option 10      # Boot Audit on Failure
ConvertFrom-CIPolicy -XmlFilePath $enforcedXml -BinaryFilePath $enforcedCip

# Rollback material is written BEFORE the operator is told how to deploy.
$rollback = Join-Path $PolicyDir 'ROLLBACK.txt'
@"
WDAC rollback for policy $($state.PolicyId)   (written $((Get-Date).ToUniversalTime().ToString('o')))

Audit policy kept for redeployment : $auditCip
Overrides used for this promotion  : $(if ($overrides) { $overrides -join ', ' } else { 'none' })

1. Redeploy the audit policy (same policy id replaces the enforced one):
     CiTool --update-policy "$auditCip"
2. Or remove the policy:
     CiTool --remove-policy $($state.PolicyId)
3. If the server cannot start services or boot: from the console, delete
     %windir%\System32\CodeIntegrity\CiPolicies\Active\$($state.PolicyId).cip
   (from recovery media if necessary) and reboot.
These steps assume an UNSIGNED policy, which is what this script builds. A signed policy cannot
be removed this way. They have not been exercised by this repository's tests.
"@ | Set-Content -LiteralPath $rollback -Encoding UTF8

[pscustomobject]@{
    Mode            = 'EnforcedBuilt'
    PolicyId        = $state.PolicyId
    AuditXmlHash    = $auditHash
    BuiltUtc        = (Get-Date).ToUniversalTime().ToString('o')
    OverridesUsed   = $overrides
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PolicyDir 'enforced-state.json') -Encoding UTF8

Write-Host "Enforced policy built: $enforcedCip (not deployed). Rollback notes: $rollback"
Write-Host "Deploy with:  CiTool --update-policy `"$enforcedCip`""
Write-Host "Keep out-of-band console access until the server has been restarted and verified."

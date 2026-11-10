<#
.SYNOPSIS
  AI-Driven End-to-End Auto-Configuration and Deployment Engine for MCP Broker.

.DESCRIPTION
  Enables an AI agent or automated orchestrator to discover host capabilities,
  generate a tailored configuration plan, sign wrapper modules, apply all
  configuration files, generate JEA artifacts, and validate system health.

  Modes:
    -Discover : Outputs structured JSON detailing OS, domain, identity, certs, and features.
    -Plan     : Generates a complete configuration profile (Development or Production).
    -Apply    : Applies a configuration profile end-to-end (signing, manifest, appsettings, JEA).
    -Validate : Evaluates health of all broker gates, files, signatures, and self-checks.
    -Full     : Runs Discover -> Plan -> Apply -> Validate in one single command.
    -Reset    : Restores manifest, appsettings, and sidecar to default template state.

.PARAMETER DevMode
  When specified, generates/applies a local development profile:
  - Generates a self-signed code signing cert if none exists
  - Uses current user SID as caller and approver
  - Disables distinct approver requirement (RequireDistinctApprover = false)
  - Sets accessGroup to BUILTIN\Users
  - Auto-revokes tools for Windows features not installed on this machine

.PARAMETER ProfilePath
  Path to profile JSON. Defaults to 'deploy/broker-profile.json'.

.PARAMETER AutoTrustCert
  When specified and running elevated, imports the self-signed certificate into
  LocalMachine\Root and LocalMachine\TrustedPublisher for system-wide trust.

.PARAMETER RepoRoot
  Path to mcp-broker repository root. Defaults to the parent directory of deploy.
#>

[CmdletBinding(DefaultParameterSetName = 'Full')]
param(
    [Parameter(ParameterSetName = 'Discover', Mandatory = $true)]
    [switch] $Discover,

    [Parameter(ParameterSetName = 'Plan', Mandatory = $true)]
    [switch] $Plan,

    [Parameter(ParameterSetName = 'Apply', Mandatory = $true)]
    [switch] $Apply,

    [Parameter(ParameterSetName = 'Validate', Mandatory = $true)]
    [switch] $Validate,

    [Parameter(ParameterSetName = 'Full')]
    [switch] $Full,

    [Parameter(ParameterSetName = 'Reset', Mandatory = $true)]
    [switch] $Reset,

    [switch] $DevMode,
    [string] $ProfilePath,
    [string] $CertThumbprint,
    [string[]] $CallerSids,
    [string[]] $ApproverSids,
    [string] $AccessGroup,
    [string] $DeployRoot,
    [string] $TranscriptDir,
    [string] $RepoRoot,
    [switch] $AutoTrustCert,
    [switch] $AllowSidecarRegeneration,
    [switch] $SkipBuild,
    [switch] $SkipTests,
    [switch] $InPlace
)

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue)) {
    try { New-PSDrive -Name Cert -PSProvider Certificate -Root '\' -Scope Global -ErrorAction SilentlyContinue | Out-Null } catch { }
}

# Resolve repository root
if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $RepoRoot = (Resolve-Path (Join-Path $scriptDir '..')).Path
}

if ([string]::IsNullOrWhiteSpace($ProfilePath)) {
    $ProfilePath = Join-Path $RepoRoot 'deploy\broker-profile.json'
}

$ManifestPath = Join-Path $RepoRoot 'policy\manifest.json'
$IntegrityPath = Join-Path $RepoRoot 'policy\manifest.json.sha256'
$AppSettingsPath = Join-Path $RepoRoot 'src\Broker.Host\appsettings.json'
$ModulesDir = Join-Path $RepoRoot 'jea\modules'
$GeneratedDir = Join-Path $RepoRoot 'jea\generated'

# Helper: Log progress to stderr so stdout remains 100% pure JSON for AI consumption
function Write-Log {
    param([string] $Message)
    [Console]::Error.WriteLine("[auto-configure] $Message")
}

# Helper: Output JSON object to stdout
function Out-JsonResult {
    param($Object)
    $json = $Object | ConvertTo-Json -Depth 20
    [Console]::Out.WriteLine($json)
}

# Helper: Compute SHA256 of a file
function Get-Sha256Hex {
    param([string] $Path)
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $hashBytes = $hasher.ComputeHash($bytes)
        return -join ($hashBytes | ForEach-Object { $_.ToString('x2') })
    }
    finally {
        $hasher.Dispose()
    }
}

# -----------------------------------------------------------------------------
# DISCOVER
# -----------------------------------------------------------------------------
function Get-BrokerDiscovery {
    Write-Log "Gathering host discovery data..."

    # System & Domain
    $machineName = [System.Environment]::MachineName
    $osVersion = [System.Environment]::OSVersion.VersionString
    $isPartOfDomain = $false
    $domainName = $machineName
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($cs) {
            $isPartOfDomain = [bool]$cs.PartOfDomain
            $domainName = $cs.Domain
        }
    }
    catch {}

    # Identity
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]$identity
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    $currentSid = $identity.User.Value
    $currentName = $identity.Name

    # Code Signing Certificates
    $certs = @()
    $certLocations = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')
    foreach ($loc in $certLocations) {
        if (Test-Path $loc) {
            foreach ($c in (Get-ChildItem -Path $loc -ErrorAction SilentlyContinue)) {
                $isCodeSigning = $false
                try {
                    foreach ($ext in $c.Extensions) {
                        if ($ext -and $ext.Oid -and $ext.Oid.Value -eq '2.5.29.37') {
                            if ($ext.Format($false) -match 'Code Signing' -or $ext.Format($true) -match '1.3.6.1.5.5.7.3.3') {
                                $isCodeSigning = $true
                                break
                            }
                        }
                    }
                }
                catch { }

                if ($isCodeSigning) {
                    $certs += [pscustomobject]@{
                        Subject       = $c.Subject
                        Thumbprint    = $c.Thumbprint
                        StoreLocation = $loc
                        NotAfter      = $c.NotAfter.ToString('o')
                        HasPrivateKey = $c.HasPrivateKey
                    }
                }
            }
        }
    }

    # Feature probing
    $features = [ordered]@{}
    $features['ActiveDirectory'] = [bool](Get-Module -ListAvailable ActiveDirectory) -or (Test-Path "$env:SystemRoot\System32\ActiveDirectory")
    $features['HyperV'] = [bool](Get-Module -ListAvailable Hyper-V) -or [bool](Get-Command Get-VM -ErrorAction SilentlyContinue)
    $features['WebAdministration'] = [bool](Get-Module -ListAvailable WebAdministration) -or [bool](Get-Command Get-IISSite -ErrorAction SilentlyContinue)
    $features['DhcpServer'] = [bool](Get-Module -ListAvailable DhcpServer)
    $features['UpdateServices'] = [bool](Get-Module -ListAvailable UpdateServices)
    $features['FailoverClusters'] = [bool](Get-Module -ListAvailable FailoverClusters)
    $features['NetworkLoadBalancingClusters'] = [bool](Get-Module -ListAvailable NetworkLoadBalancingClusters)
    $features['DnsServer'] = [bool](Get-Module -ListAvailable DnsServer)
    $features['BitLocker'] = [bool](Get-Module -ListAvailable BitLocker)
    $features['ScheduledTasks'] = [bool](Get-Module -ListAvailable ScheduledTasks)

    # Windows Service Status
    $svc = Get-Service -Name 'McpBroker' -ErrorAction SilentlyContinue
    $serviceInfo = if ($svc) {
        [pscustomobject]@{
            Installed = $true
            Status    = $svc.Status.ToString()
            StartType = $svc.StartType.ToString()
        }
    }
    else {
        [pscustomobject]@{ Installed = $false; Status = 'NotInstalled'; StartType = $null }
    }

    # JEA Session Configurations
    $jeaEndpoints = @()
    try {
        Get-PSSessionConfiguration -Name 'McpBroker.*' -ErrorAction SilentlyContinue | ForEach-Object {
            $jeaEndpoints += [pscustomobject]@{
                Name      = $_.Name
                RunningAs = $_.RunAsUser
                State     = 'Registered'
            }
        }
    }
    catch {}

    # Manifest Inspection
    $manifestJson = Get-Content $ManifestPath -Raw -ErrorAction Stop | ConvertFrom-Json
    $totalTools = @($manifestJson.tools).Count
    $readTools = @($manifestJson.tools | Where-Object { $_.riskTier -eq 'read' }).Count
    $writeTools = @($manifestJson.tools | Where-Object { $_.riskTier -eq 'write' }).Count
    $activeTools = @($manifestJson.tools | Where-Object { -not ($_.PSObject.Properties.Match('revoked').Count -gt 0 -and $_.revoked) }).Count
    $revokedTools = @($manifestJson.tools | Where-Object { $_.PSObject.Properties.Match('revoked').Count -gt 0 -and $_.revoked }).Count
    $placeholderThumbprints = @($manifestJson.tools | Where-Object { $_.server.signatureThumbprint -match '^A{40}$' }).Count
    $placeholderAccessGroups = @($manifestJson.tools | Where-Object { $_.jeaMapping.accessGroup -eq 'CONTOSO\McpBrokerCallers' }).Count

    # AppSettings Inspection
    $appSettingsJson = Get-Content $AppSettingsPath -Raw -ErrorAction Stop | ConvertFrom-Json
    $allowedSids = @($appSettingsJson.Pipe.AllowedSids)
    $hasPlaceholderSid = [bool]($allowedSids | Where-Object { $_ -match '^S-1-5-21-0000000000-' })
    $approverSids = @($appSettingsJson.Elicitation.ApproverSids)
    $requireDistinctApprover = [bool]$appSettingsJson.Elicitation.RequireDistinctApprover

    # Sidecar Integrity Inspection
    $sidecarHash = if (Test-Path $IntegrityPath) { (Get-Content $IntegrityPath -Raw).Trim() } else { $null }
    $actualHash = Get-Sha256Hex -Path $ManifestPath
    $integrityValid = ($sidecarHash -eq $actualHash)

    return [pscustomobject]@{
        Timestamp               = (Get-Date).ToString('o')
        Machine                 = [pscustomobject]@{
            Name           = $machineName
            OSVersion      = $osVersion
            IsDomainJoined = $isPartOfDomain
            Domain         = $domainName
        }
        Identity                = [pscustomobject]@{
            CurrentUser     = $currentName
            CurrentSid      = $currentSid
            IsAdministrator = $isAdmin
        }
        CodeSigningCertificates = $certs
        Features                = $features
        Service                 = $serviceInfo
        JeaEndpoints            = $jeaEndpoints
        Manifest                = [pscustomobject]@{
            TotalTools              = $totalTools
            ReadTools               = $readTools
            WriteTools              = $writeTools
            ActiveTools             = $activeTools
            RevokedTools            = $revokedTools
            PlaceholderThumbprints  = $placeholderThumbprints
            PlaceholderAccessGroups = $placeholderAccessGroups
            IntegrityValid          = $integrityValid
        }
        AppSettings             = [pscustomobject]@{
            AllowedSids             = $allowedSids
            HasPlaceholderSid       = $hasPlaceholderSid
            ApproverSids            = $approverSids
            RequireDistinctApprover = $requireDistinctApprover
        }
    }
}

# -----------------------------------------------------------------------------
# PLAN
# -----------------------------------------------------------------------------
function New-BrokerPlan {
    param(
        $DiscoveryData,
        [switch] $IsDevMode
    )

    Write-Log "Generating configuration plan..."

    if (-not $DiscoveryData) {
        $DiscoveryData = Get-BrokerDiscovery
    }

    # Determine mode: explicit DevMode only; never silently select DevMode on non-domain hosts
    $effectiveDevMode = [bool]$IsDevMode

    # Resolve Signing Strategy (Operator-only: Enterprise CA cert required in production)
    $signingStrategy = 'CreateSelfSigned'
    $targetThumbprint = $CertThumbprint
    if (-not $effectiveDevMode) {
        if ([string]::IsNullOrWhiteSpace($targetThumbprint)) {
            throw "Production mode requires an explicit enterprise CA Code Signing certificate thumbprint via -CertThumbprint."
        }
        $signingStrategy = 'UseExistingCert'
    }
    elseif (-not [string]::IsNullOrWhiteSpace($targetThumbprint)) {
        $signingStrategy = 'UseExistingCert'
    }
    elseif ($DiscoveryData.CodeSigningCertificates.Count -gt 0) {
        $signingStrategy = 'UseExistingCert'
        $targetThumbprint = $DiscoveryData.CodeSigningCertificates[0].Thumbprint
    }
    else {
        $signingStrategy = 'CreateSelfSigned'
        $targetThumbprint = $null
    }

    # Resolve Caller & Approver SIDs
    $effectiveCallerSids = if ($CallerSids -and $CallerSids.Count -gt 0) {
        @($CallerSids)
    }
    else {
        @($DiscoveryData.Identity.CurrentSid)
    }

    $effectiveRequireDistinct = if ($effectiveDevMode) { $false } else { $true }
    $effectiveApproverSids = if ($ApproverSids -and $ApproverSids.Count -gt 0) {
        @($ApproverSids)
    }
    elseif ($effectiveDevMode) {
        # DevMode default approver SID must be disjoint from caller SID to satisfy Invariant 1
        @('S-1-5-21-999999999-999999999-999999999-9999')
    }
    else {
        @()
    }

    # Enforce Invariant 1: Caller SIDs and Approver SIDs are disjoint
    $callerSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$effectiveCallerSids, [System.StringComparer]::OrdinalIgnoreCase)
    $overlapping = @($effectiveApproverSids | Where-Object { $callerSet.Contains($_) })
    if ($overlapping.Count -gt 0) {
        throw "Invariant 1 violation: CallerSids and ApproverSids must be disjoint. Overlapping SIDs: $($overlapping -join ', ')"
    }

    # Resolve Access Group (Invariant 3: reject broad groups like BUILTIN\Users)
    $effectiveAccessGroup = if (-not [string]::IsNullOrWhiteSpace($AccessGroup)) {
        $AccessGroup
    }
    elseif ($effectiveDevMode) {
        'McpBrokerServiceGroup'
    }
    else {
        "$($DiscoveryData.Machine.Domain)\McpBrokerCallers"
    }

    $broadGroups = @('BUILTIN\Users', 'Users', 'Domain Users', 'Authenticated Users', 'Everyone', 'Interactive')
    if ($broadGroups -contains $effectiveAccessGroup) {
        throw "Invariant 3 violation: accessGroup '$effectiveAccessGroup' is a broad group and is prohibited."
    }

    # Resolve Paths
    $effectiveInPlace = if ($PSBoundParameters.ContainsKey('InPlace')) { [bool]$InPlace } else { $effectiveDevMode }
    $effectiveDeployRoot = if (-not [string]::IsNullOrWhiteSpace($DeployRoot)) {
        $DeployRoot
    }
    elseif ($effectiveInPlace) {
        $RepoRoot
    }
    else {
        'C:\McpBroker'
    }

    $effectiveTranscriptDir = if (-not [string]::IsNullOrWhiteSpace($TranscriptDir)) {
        $TranscriptDir
    }
    else {
        Join-Path $effectiveDeployRoot 'Transcripts'
    }

    # Determine Tools to Revoke (tools whose host features are absent)
    $revokeList = @()
    if (-not $DiscoveryData.Features['ActiveDirectory']) {
        $revokeList += @(
            'query-ad-user',
            'list-group-policies',
            'list-ad-computers',
            'list-ad-groups',
            'get-domain-password-policy',
            'list-fine-grained-password-policies',
            'list-ad-organizational-units',
            'list-read-only-domain-controllers',
            'set-ad-user-enabled',
            'set-ad-computer-enabled',
            'set-ad-group-membership',
            'set-gpo-status'
        )
    }
    if (-not $DiscoveryData.Features['HyperV']) {
        $revokeList += @('list-hyperv-vms', 'set-hyperv-vm-state')
    }
    if (-not $DiscoveryData.Features['WebAdministration']) {
        $revokeList += @('list-iis-sites', 'list-ftp-sites', 'set-iis-site-state')
    }
    if (-not $DiscoveryData.Features['DhcpServer']) {
        $revokeList += @('list-dhcp-scopes', 'set-dhcp-scope-state')
    }
    if (-not $DiscoveryData.Features['UpdateServices']) {
        $revokeList += @('list-wsus-updates', 'set-wsus-update-approval')
    }
    if (-not $DiscoveryData.Features['FailoverClusters']) {
        $revokeList += @('list-cluster-nodes', 'set-cluster-node-state')
    }
    if (-not $DiscoveryData.Features['NetworkLoadBalancingClusters']) {
        $revokeList += @('list-nlb-clusters')
    }
    if (-not $DiscoveryData.Features['DnsServer']) {
        $revokeList += @('list-dns-zones')
    }
    if (-not $DiscoveryData.Features['BitLocker']) {
        $revokeList += @('list-bitlocker-volumes')
    }

    # Allowed Directory Roots for list-directory-contents
    $allowedRoots = @('C:\Shares', 'C:\Data', 'D:\Shares', 'D:\Data')

    $profile = [ordered]@{
        '$schema'      = 'mcp-broker-config-profile-v1'
        mode           = if ($effectiveDevMode) { 'Development' } else { 'Production' }
        signing        = [ordered]@{
            strategy   = $signingStrategy
            thumbprint = $targetThumbprint
            subject    = 'CN=McpBrokerDevCert'
            certStore  = 'Cert:\CurrentUser\My'
        }
        identity       = [ordered]@{
            callerSids              = @($effectiveCallerSids)
            approverSids            = @($effectiveApproverSids)
            requireDistinctApprover = $effectiveRequireDistinct
            accessGroup             = $effectiveAccessGroup
        }
        paths          = [ordered]@{
            inPlace        = [bool]$effectiveInPlace
            deployRoot     = $effectiveDeployRoot
            transcriptDir  = $effectiveTranscriptDir
            correlationLog = (Join-Path $effectiveDeployRoot 'correlation.log')
        }
        directoryRoots = $allowedRoots
        tools          = [ordered]@{
            revokeTools = ($revokeList | Sort-Object -Unique)
        }
    }

    $profileJson = $profile | ConvertTo-Json -Depth 20
    $profileDir = Split-Path -Parent $ProfilePath
    if (-not (Test-Path $profileDir)) { New-Item -ItemType Directory -Path $profileDir -Force | Out-Null }
    [System.IO.File]::WriteAllText($ProfilePath, $profileJson, [System.Text.Encoding]::UTF8)
    Write-Log "Saved configuration plan to '$ProfilePath'."

    return $profile
}

# -----------------------------------------------------------------------------
# APPLY
# -----------------------------------------------------------------------------
function Invoke-BrokerApply {
    param(
        $Profile
    )

    Write-Log "Applying configuration profile..."
    $results = [ordered]@{}

    # 1. Certificate Resolution & Signing Setup
    Write-Log "Step 1/7: Preparing code signing certificate..."
    $cerPath = Join-Path $RepoRoot 'deploy\McpBrokerDevCert.cer'
    $cert = $null
    if ($Profile.signing.strategy -eq 'CreateSelfSigned') {
        if (-not (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue)) {
            try { New-PSDrive -Name Cert -PSProvider Certificate -Root '\' -Scope Global -ErrorAction SilentlyContinue | Out-Null } catch { }
        }
        $subject = $Profile.signing.subject
        $existing = Get-ChildItem -Path 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -eq $subject } | Select-Object -First 1

        if ($existing) {
            $cert = $existing
            Write-Log "Found existing dev certificate: $($cert.Thumbprint)"
        }
        else {
            Write-Log "Generating new self-signed code signing certificate '$subject'..."
            Push-Location 'Cert:\CurrentUser\My'
            try {
                $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject -NotAfter (Get-Date).AddYears(5)
            }
            finally {
                Pop-Location
            }
            Write-Log "Created certificate with thumbprint $($cert.Thumbprint)."
        }

        # Add to TrustedPublisher for CurrentUser
        try {
            $tpStore = New-Object System.Security.Cryptography.X509Certificates.X509Store(
                [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPublisher,
                [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
            $tpStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $tpStore.Add($cert)
            $tpStore.Close()
        }
        catch {
            Write-Log "Warning: Could not add cert to CurrentUser\TrustedPublisher: $_"
        }

        # Export public .cer
        Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
        Write-Log "Exported public certificate to '$cerPath'."

        # Notice: Never auto-trust or import self-signed certificates into LocalMachine\Root or
        # LocalMachine\TrustedPublisher. Trust anchors must only be deployed via enterprise PKI or Group Policy.
        Write-Log "Self-signed certificate is confined to CurrentUser store. System trust stores unmodified."
    }
    else {
        $thumb = $Profile.signing.thumbprint
        $cert = Get-ChildItem -Path 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
        if (-not $cert) {
            throw "Configured certificate thumbprint '$thumb' not found in Cert:\CurrentUser\My or Cert:\LocalMachine\My."
        }
        Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
    }

    $actualThumbprint = $cert.Thumbprint
    $results['SigningCertificate'] = [pscustomobject]@{
        Subject       = $cert.Subject
        Thumbprint    = $actualThumbprint
        HasPrivateKey = $cert.HasPrivateKey
    }

    # 2. Sign all wrapper .psm1 modules
    Write-Log "Step 2/7: Signing all wrapper modules in '$ModulesDir'..."
    $signedCount = 0
    Get-ChildItem -Path $ModulesDir -Filter '*.psm1' | ForEach-Object {
        $sig = Set-AuthenticodeSignature -FilePath $_.FullName -Certificate $cert -HashAlgorithm SHA256
        $signedCount++
    }
    Write-Log "Successfully signed $signedCount modules with thumbprint $actualThumbprint."
    $results['SignedModulesCount'] = $signedCount

    # 3. Deploy/Stage Modules to PSModulePath
    Write-Log "Step 3/7: Staging modules for JEA resolution..."
    # Always stage into user's documents PSModulePath (accessible without admin)
    $userDocModules = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Modules'
    if (-not (Test-Path $userDocModules)) { New-Item -ItemType Directory -Path $userDocModules -Force | Out-Null }
    Get-ChildItem -Path $ModulesDir -Filter '*.psm1' | ForEach-Object {
        $modName = $_.BaseName
        $targetDir = Join-Path $userDocModules $modName
        if (-not (Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }
        Copy-Item -Path $_.FullName -Destination (Join-Path $targetDir "$modName.psm1") -Force
    }

    # Also deploy to DeployRoot if not in-place
    $targetModuleDir = $ModulesDir
    if (-not $Profile.paths.inPlace) {
        $deployJea = Join-Path $Profile.paths.deployRoot 'jea'
        if (-not (Test-Path $deployJea)) { New-Item -ItemType Directory -Path $deployJea -Force | Out-Null }
        Get-ChildItem -Path $ModulesDir -Filter '*.psm1' | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination (Join-Path $deployJea $_.Name) -Force
        }
        $targetModuleDir = $deployJea
        Write-Log "Staged modules into '$deployJea'."
    }
    $results['ModulesStagedPath'] = $targetModuleDir

    # 4. Manifest handling: In production, manifest and sidecar are produced off-host
    if ($Profile.mode -eq 'Production') {
        Write-Log "Step 4/7: Verifying off-host manifest and integrity sidecar..."
        $manifestSha256 = Get-Sha256Hex -Path $ManifestPath
        $sidecarHash = if (Test-Path $IntegrityPath) { (Get-Content -LiteralPath $IntegrityPath -Raw).Trim() } else { '' }
        if ([string]::IsNullOrWhiteSpace($sidecarHash) -or $sidecarHash -ne $manifestSha256) {
            throw "Manifest integrity violation: manifest.json SHA256 ($manifestSha256) does not match manifest.json.sha256 sidecar ($sidecarHash). The sidecar must be produced off-host in a trusted release pipeline."
        }
        $results['ManifestSha256'] = $manifestSha256
        Write-Log "Verified off-host manifest matches integrity sidecar."
    }
    else {
        # DevMode: Update manifest with dev cert and access group
        Write-Log "Step 4/7: Updating manifest.json (DevMode)..."
        $manifest = Get-Content -LiteralPath $ManifestPath -Raw -ErrorAction Stop | ConvertFrom-Json
        $revokeSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$Profile.tools.revokeTools, [System.StringComparer]::OrdinalIgnoreCase)

        foreach ($tool in $manifest.tools) {
            # Update server reference
            $tool.server.signatureThumbprint = $actualThumbprint
            $moduleFileName = "$($tool.jeaMapping.moduleName).psm1"
            $tool.server.path = Join-Path $targetModuleDir $moduleFileName

            # Update access group
            $tool.jeaMapping.accessGroup = $Profile.identity.accessGroup

            # Update revocation state
            if ($revokeSet.Contains($tool.toolId)) {
                $tool | Add-Member -NotePropertyName 'revoked' -NotePropertyValue $true -Force
            }
            elseif ($tool.PSObject.Properties.Match('revoked').Count -gt 0) {
                $tool.revoked = $false
            }
        }

        # Save manifest with clean indenting
        $updatedManifestJson = $manifest | ConvertTo-Json -Depth 20
        [System.IO.File]::WriteAllText($ManifestPath, $updatedManifestJson, [System.Text.Encoding]::UTF8)

        # 5. Compute and update manifest.json.sha256 sidecar
        Write-Log "Step 5/7: Generating manifest integrity sidecar (DevMode)..."
        $manifestSha256 = Get-Sha256Hex -Path $ManifestPath
        [System.IO.File]::WriteAllText($IntegrityPath, $manifestSha256, [System.Text.Encoding]::ASCII)
        $results['ManifestSha256'] = $manifestSha256
    }

    # 6. Update src/Broker.Host/appsettings.json
    Write-Log "Step 6/7: Updating appsettings.json..."
    $appSettings = Get-Content -LiteralPath $AppSettingsPath -Raw -ErrorAction Stop | ConvertFrom-Json
    $appSettings.Pipe.AllowedSids = @($Profile.identity.callerSids)
    $appSettings.Elicitation.ApproverSids = @($Profile.identity.approverSids)
    $appSettings.Elicitation.RequireDistinctApprover = [bool]$Profile.identity.requireDistinctApprover
    if ($Profile.paths.transcriptDir) {
        $appSettings.Jea.TranscriptDir = $Profile.paths.transcriptDir
    }
    if ($Profile.paths.correlationLog) {
        $appSettings.Audit.CorrelationLogPath = $Profile.paths.correlationLog
    }

    $updatedAppSettingsJson = $appSettings | ConvertTo-Json -Depth 20
    [System.IO.File]::WriteAllText($AppSettingsPath, $updatedAppSettingsJson, [System.Text.Encoding]::UTF8)
    $results['AppSettingsUpdated'] = $true

    # 7. Regenerate JEA artifacts
    Write-Log "Step 7/7: Regenerating JEA artifacts..."
    Push-Location $RepoRoot
    try {
        $hostDll = @(
            (Join-Path $RepoRoot 'src\Broker.Host\bin\Release\net8.0-windows\Broker.Host.dll'),
            (Join-Path $RepoRoot 'src\Broker.Host\bin\Debug\net8.0-windows\Broker.Host.dll')
        ) | Where-Object { Test-Path $_ } | Select-Object -First 1

        if ($hostDll) {
            $genOutput = & dotnet $hostDll generate-jea policy/manifest.json jea/generated 2>&1
        }
        else {
            $genOutput = & dotnet run --no-restore --project src/Broker.Host -- generate-jea policy/manifest.json jea/generated 2>&1
        }

        if ($LASTEXITCODE -ne 0) {
            throw "JEA generation failed with exit code $LASTEXITCODE. Output: $genOutput"
        }
        $results['JeaGenerationExitCode'] = 0

        # Build solution
        if (-not $SkipBuild) {
            Write-Log "Building solution in Release configuration..."
            $buildOutput = & dotnet build --no-restore mcp-broker.sln -c Release 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "Release build failed with exit code $LASTEXITCODE. Output: $buildOutput"
            }
            $results['BuildExitCode'] = 0
        }
    }
    finally {
        Pop-Location
    }

    # Check elevation requirements for JEA registration & service setup
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = ([System.Security.Principal.WindowsPrincipal]$identity).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    $results['IsElevated'] = $isAdmin

    if ($isAdmin) {
        Write-Log "Host is running elevated: registering JEA endpoints..."
        try {
            & (Join-Path $RepoRoot 'deploy\register-jea.ps1') -GeneratedDir $GeneratedDir -ModulesSourceDir $ModulesDir
            $results['JeaRegistration'] = 'Succeeded'
        }
        catch {
            $results['JeaRegistration'] = "Failed: $_"
        }
    }
    else {
        $results['JeaRegistration'] = 'PendingElevation'
        $results['RequiredElevationCommands'] = @(
            "Import-Certificate -FilePath '$cerPath' -CertStoreLocation Cert:\LocalMachine\Root",
            "Import-Certificate -FilePath '$cerPath' -CertStoreLocation Cert:\LocalMachine\TrustedPublisher",
            "powershell.exe -ExecutionPolicy Bypass -File '$RepoRoot\deploy\register-jea.ps1' -GeneratedDir '$GeneratedDir'"
        )
        Write-Log "Note: JEA registration and system root trust require Administrator privileges."
    }

    $results['Status'] = 'Applied'
    return [pscustomobject]$results
}

# -----------------------------------------------------------------------------
# VALIDATE
# -----------------------------------------------------------------------------
function Invoke-BrokerValidate {
    Write-Log "Validating broker configuration and health..."
    $checks = [ordered]@{}
    $allOk = $true

    # 1. Manifest Placeholders
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    $activeTools = @($manifest.tools | Where-Object { -not ($_.PSObject.Properties.Match('revoked').Count -gt 0 -and $_.revoked) })
    $placeholderThumbprints = @($activeTools | Where-Object { $_.server.signatureThumbprint -match '^A{40}$' }).Count
    $checks['ActiveToolsCount'] = $activeTools.Count
    $checks['RevokedToolsCount'] = @($manifest.tools | Where-Object { $_.PSObject.Properties.Match('revoked').Count -gt 0 -and $_.revoked }).Count
    $checks['ZeroPlaceholderThumbprints'] = ($placeholderThumbprints -eq 0)
    if ($placeholderThumbprints -gt 0) { $allOk = $false }

    # 2. AppSettings Placeholders
    $appSettings = Get-Content -LiteralPath $AppSettingsPath -Raw | ConvertFrom-Json
    $placeholderSids = @($appSettings.Pipe.AllowedSids | Where-Object { $_ -match '^S-1-5-21-0000000000-' }).Count
    $checks['ZeroPlaceholderSids'] = ($placeholderSids -eq 0)
    if ($placeholderSids -gt 0) { $allOk = $false }

    # 3. Distinct Approver & Disjointness Check (Invariant 1)
    $distinctOk = $true
    $disjointOk = $true
    if ($appSettings.Elicitation.RequireDistinctApprover) {
        $approvers = @($appSettings.Elicitation.ApproverSids)
        if ($approvers.Count -eq 0 -or @($approvers | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
            $distinctOk = $false
            $allOk = $false
        }
        $callers = @($appSettings.Pipe.AllowedSids)
        $overlaps = @($callers | Where-Object { $approvers -contains $_ })
        if ($overlaps.Count -gt 0) {
            $disjointOk = $false
            $allOk = $false
        }
    }
    $checks['ApproverSidsConfigured'] = $distinctOk
    $checks['ApproverSidsDisjoint'] = $disjointOk

    # 4. Manifest Integrity Sidecar
    $sidecarHash = if (Test-Path $IntegrityPath) { (Get-Content $IntegrityPath -Raw).Trim() } else { '' }
    $actualHash = Get-Sha256Hex -Path $ManifestPath
    $checks['ManifestIntegrityMatches'] = ($sidecarHash -eq $actualHash)
    if ($sidecarHash -ne $actualHash) { $allOk = $false }

    # 5. Modules Signed Check (H3: status must be Valid, never HashMismatch or NotSigned)
    $invalidModules = @()
    Get-ChildItem -Path $ModulesDir -Filter '*.psm1' | ForEach-Object {
        $sig = Get-AuthenticodeSignature -FilePath $_.FullName
        if ($sig.Status -ne 'Valid') {
            $invalidModules += [pscustomobject]@{ Name = $_.Name; Status = $sig.Status.ToString() }
        }
    }
    $checks['AllModulesSigned'] = ($invalidModules.Count -eq 0)
    if ($invalidModules.Count -gt 0) { $allOk = $false }

    # 6. JEA Artifacts
    $psrcCount = @(Get-ChildItem -Path $GeneratedDir -Filter '*.psrc' -ErrorAction SilentlyContinue).Count
    $psscCount = @(Get-ChildItem -Path $GeneratedDir -Filter '*.pssc' -ErrorAction SilentlyContinue).Count
    $checks['GeneratedRoleCapabilitiesCount'] = $psrcCount
    $checks['GeneratedSessionConfigsCount'] = $psscCount
    $checks['JeaArtifactsPresent'] = ($psrcCount -gt 0 -and $psscCount -gt 0)
    if ($psrcCount -eq 0) { $allOk = $false }

    # 7. Unit Tests
    if (-not $SkipTests) {
        Write-Log "Running automated test suite..."
        Push-Location $RepoRoot
        try {
            $testOutput = & dotnet test --no-restore mcp-broker.sln 2>&1
            $checks['UnitTestsPassed'] = ($LASTEXITCODE -eq 0)
            if ($LASTEXITCODE -ne 0) { $allOk = $false }
        }
        finally {
            Pop-Location
        }
    }
    else {
        $checks['UnitTestsPassed'] = 'Skipped'
        # H3: Never report Healthy when tests were skipped.
        $allOk = $false
    }

    $status = if ($allOk) { 'Healthy' } else { 'ActionRequired' }

    return [pscustomobject]@{
        Status    = $status
        Timestamp = (Get-Date).ToString('o')
        Checks    = [pscustomobject]$checks
    }
}

# -----------------------------------------------------------------------------
# RESET
# -----------------------------------------------------------------------------
function Reset-BrokerConfig {
    Write-Log "Cleaning up local profile artifacts and stripping module signatures..."
    Push-Location $RepoRoot
    try {
        $cer = Join-Path $RepoRoot 'deploy\McpBrokerDevCert.cer'
        $prof = Join-Path $RepoRoot 'deploy\broker-profile.json'
        if (Test-Path $cer) { Remove-Item -Path $cer -Force -ErrorAction SilentlyContinue }
        if (Test-Path $prof) { Remove-Item -Path $prof -Force -ErrorAction SilentlyContinue }

        # Strip signature blocks from wrapper modules so they return to unsigned state without losing working-tree edits
        Get-ChildItem -Path $ModulesDir -Filter '*.psm1' -ErrorAction SilentlyContinue | ForEach-Object {
            $content = [System.IO.File]::ReadAllText($_.FullName)
            if ($content -match '(?s)\r?\n# SIG # Begin signature block.*$') {
                $cleaned = $content -replace '(?s)\r?\n# SIG # Begin signature block.*$', ''
                $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
                [System.IO.File]::WriteAllText($_.FullName, $cleaned, $utf8NoBom)
            }
        }

        return [pscustomobject]@{
            Status   = 'ResetComplete'
            ExitCode = 0
        }
    }
    finally {
        Pop-Location
    }
}

# -----------------------------------------------------------------------------
# DISPATCHER
# -----------------------------------------------------------------------------
try {
    switch ($PSCmdlet.ParameterSetName) {
        'Discover' {
            $discovery = Get-BrokerDiscovery
            Out-JsonResult $discovery
            break
        }
        'Plan' {
            $profile = New-BrokerPlan -IsDevMode:$DevMode
            Out-JsonResult $profile
            break
        }
        'Apply' {
            $profile = if (Test-Path $ProfilePath) {
                Get-Content -LiteralPath $ProfilePath -Raw | ConvertFrom-Json
            }
            else {
                New-BrokerPlan -IsDevMode:$DevMode
            }
            $result = Invoke-BrokerApply -Profile $profile
            Out-JsonResult $result
            break
        }
        'Validate' {
            $val = Invoke-BrokerValidate
            Out-JsonResult $val
            break
        }
        'Reset' {
            $res = Reset-BrokerConfig
            Out-JsonResult $res
            break
        }
        'Full' {
            Write-Log "Running Full Auto-Configuration pipeline..."
            $discovery = Get-BrokerDiscovery
            $profile = New-BrokerPlan -DiscoveryData $discovery -IsDevMode:$DevMode
            $applyResult = Invoke-BrokerApply -Profile $profile
            $val = Invoke-BrokerValidate

            $summary = [pscustomobject]@{
                Pipeline      = 'Full'
                Status        = $val.Status
                Discovery     = [pscustomobject]@{
                    Machine        = $discovery.Machine.Name
                    Domain         = $discovery.Machine.Domain
                    IsDomainJoined = $discovery.Machine.IsDomainJoined
                    CurrentUser    = $discovery.Identity.CurrentUser
                    CurrentSid     = $discovery.Identity.CurrentSid
                }
                Configuration = [pscustomobject]@{
                    Mode              = $profile.mode
                    SigningThumbprint = $applyResult.SigningCertificate.Thumbprint
                    ActiveTools       = $val.Checks.ActiveToolsCount
                    RevokedTools      = $val.Checks.RevokedToolsCount
                }
                Validation    = $val.Checks
                Elevation     = [pscustomobject]@{
                    IsElevated                = $applyResult.IsElevated
                    RequiredElevationCommands = $applyResult.RequiredElevationCommands
                }
            }
            Out-JsonResult $summary
            break
        }
    }
}
catch {
    $errObj = [pscustomobject]@{
        Status     = 'Failed'
        Error      = $_.Exception.Message
        StackTrace = $_.ScriptStackTrace
    }
    Out-JsonResult $errObj
    exit 1
}

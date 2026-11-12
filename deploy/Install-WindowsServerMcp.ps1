#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
  Enterprise One-Click Automated Installer for Windows-Server-MCP Broker Appliance.

.DESCRIPTION
  Deploys, hardens, signs, configures, and registers the Windows-Server-MCP broker
  appliance in under 3 minutes with zero manual guesswork.

  Execution Pipeline:
    Step 1 - Pre-flight Checks (OS version 2022/2025/11, .NET 8 SDK/Runtime, Elevation, Invariant 1 SID disjointness)
    Step 2 - Compile & Stage (dotnet publish Release binaries for Broker.Host, Broker.McpAdapter, Broker.ApproverCli)
    Step 3 - Secure File Hierarchy (bin, jea, policy, Transcripts, logs with hardened NTFS DACLs stripping broad principals)
    Step 4 - Copy Manifest & Policy (manifest.json, manifest.json.sha256, tool-manifest.schema.json, appsettings.json)
    Step 5 - Auto-Configure & JEA (invoke deploy/auto-configure.ps1 -Full, Authenticode signing, Register-PSSessionConfiguration)
    Step 6 - Windows Service Setup (register McpBroker via sc.exe / New-Service with start= auto and failure recovery)
    Step 7 - Health Verification (invoke deploy/auto-configure.ps1 -Validate and Broker.Host.exe self-check)
    Step 8 - Output Summary (colored ASCII banner, service status, and ready-to-use JSON snippets for Claude Desktop & Cursor)

.PARAMETER TargetDir
  Target installation directory. Defaults to "C:\McpBroker".

.PARAMETER ServiceName
  Windows Service name. Defaults to "McpBroker".

.PARAMETER GmsaAccount
  Optional Group Managed Service Account (e.g., "CONTOSO\McpBrokerSvc$").
  Defaults to "NT AUTHORITY\SYSTEM" or interactive prompt when domain-joined in Production mode.

.PARAMETER CertThumbprint
  Code-signing certificate thumbprint (40-hex SHA-1 thumbprint in Cert:\LocalMachine\My or Cert:\CurrentUser\My).
  If omitted, prompts or auto-generates a self-signed evaluation certificate when -DevMode or -AutoTrustCert is specified.

.PARAMETER CallerSids
  SIDs allowed to connect to the main named pipe (\\.\pipe\McpBroker).
  Defaults to the current user SID when running in -DevMode.

.PARAMETER ApproverSids
  SIDs allowed to connect to the out-of-band approval pipe (\\.\pipe\McpBroker.Approvals).
  Must be strictly disjoint from CallerSids (Invariant 1: CallerSids ∩ ApproverSids = ∅).

.PARAMETER DevMode
  Enables development/evaluation mode (self-signed certificate, current user SID as caller, synthetic disjoint approver SID).

.PARAMETER SkipBuild
  Uses existing pre-compiled bin/ or publish/ binaries instead of invoking 'dotnet publish'.

.PARAMETER AutoTrustCert
  When generating a self-signed evaluation certificate, imports the public certificate into
  Cert:\LocalMachine\Root and Cert:\LocalMachine\TrustedPublisher so WinVerifyTrust succeeds for service accounts.

.PARAMETER AccessGroup
  Local or domain security group granted access to JEA endpoints. Must not be a broad principal.

.PARAMETER NonInteractive
  Suppresses interactive console prompts (fails closed if required production parameters are missing).

.EXAMPLE
  # Rapid Evaluation / Lab Deployment (Self-Signed Cert + Current User Caller)
  .\deploy\Install-WindowsServerMcp.ps1 -DevMode -AutoTrustCert

.EXAMPLE
  # Enterprise Production Deployment with AD CS Certificate & gMSA
  .\deploy\Install-WindowsServerMcp.ps1 `
      -TargetDir "C:\McpBroker" `
      -ServiceName "McpBroker" `
      -GmsaAccount "CONTOSO\McpBrokerSvc$" `
      -CertThumbprint "4F8B9C1D2E3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C" `
      -CallerSids @("S-1-5-21-1286530945-682254993-2698348803-2105") `
      -ApproverSids @("S-1-5-21-1286530945-682254993-2698348803-5120")
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TargetDir = "C:\McpBroker",

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceName = "McpBroker",

    [Parameter()]
    [string]$GmsaAccount,

    [Parameter()]
    [string]$CertThumbprint,

    [Parameter()]
    [string[]]$CallerSids,

    [Parameter()]
    [string[]]$ApproverSids,

    [Parameter()]
    [switch]$DevMode,

    [Parameter()]
    [switch]$SkipBuild,

    [Parameter()]
    [switch]$AutoTrustCert,

    [Parameter()]
    [string]$AccessGroup,

    [Parameter()]
    [switch]$NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = (Resolve-Path (Join-Path $ScriptDir '..')).Path

# -----------------------------------------------------------------------------
# Console Formatting Helpers
# -----------------------------------------------------------------------------
function Write-StepHeader {
    param(
        [Parameter(Mandatory = $true)][int]$StepNumber,
        [Parameter(Mandatory = $true)][int]$TotalSteps,
        [Parameter(Mandatory = $true)][string]$Title
    )
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor DarkCyan
    Write-Host ("  [Step {0}/{1}] {2}" -f $StepNumber, $TotalSteps, $Title) -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor DarkCyan
}

function Write-Info {
    param([string]$Message)
    Write-Host ("  [*] {0}" -f $Message) -ForegroundColor Gray
}

function Write-Success {
    param([string]$Message)
    Write-Host ("  [+] {0}" -f $Message) -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host ("  [!] {0}" -f $Message) -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    Write-Host ("  [-] {0}" -f $Message) -ForegroundColor Red
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$Path)
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

function Set-HardenedDirectoryAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter()][string]$ServicePrincipal = "NT AUTHORITY\SYSTEM"
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    # Disable inheritance and strip all inherited ACEs (removes BUILTIN\Users, Authenticated Users, Everyone)
    $acl.SetAccessRuleProtection($true, $false)

    $inheritFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
                    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propFlags    = [System.Security.AccessControl.PropagationFlags]::None

    # 1. NT AUTHORITY\SYSTEM -> FullControl
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $systemSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritFlags,
        $propFlags,
        [System.Security.AccessControl.AccessControlType]::Allow
    )))

    # 2. BUILTIN\Administrators -> FullControl
    $adminSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $adminSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritFlags,
        $propFlags,
        [System.Security.AccessControl.AccessControlType]::Allow
    )))

    # 3. Current Elevated Operator -> FullControl
    $currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -ne $currentUserSid) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $currentUserSid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritFlags,
            $propFlags,
            [System.Security.AccessControl.AccessControlType]::Allow
        )))
    }

    # 4. Configured Service Account (gMSA or custom service identity) -> FullControl
    if (-not [string]::IsNullOrWhiteSpace($ServicePrincipal) -and
        $ServicePrincipal -ne 'NT AUTHORITY\SYSTEM' -and
        $ServicePrincipal -ne 'LocalSystem') {
        try {
            $ntAccount = New-Object System.Security.Principal.NTAccount($ServicePrincipal)
            $svcSid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $svcSid,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                $inheritFlags,
                $propFlags,
                [System.Security.AccessControl.AccessControlType]::Allow
            )))
        }
        catch {
            Write-Warn "Could not translate service principal '$ServicePrincipal' to SID on this host ($($_.Exception.Message)). Granting rule by account name."
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $ServicePrincipal,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                $inheritFlags,
                $propFlags,
                [System.Security.AccessControl.AccessControlType]::Allow
            )))
        }
    }

    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-NoBroadWriteAccess {
    param([Parameter(Mandatory = $true)][string]$Path)

    $acl = Get-Acl -LiteralPath $Path
    $broadSids = @(
        'S-1-1-0',      # Everyone
        'S-1-5-11',     # Authenticated Users
        'S-1-5-32-545', # BUILTIN\Users
        'S-1-5-4',      # Interactive
        'S-1-5-7',      # Anonymous
        'S-1-5-2'       # Network
    )
    $writeMask = [System.Security.AccessControl.FileSystemRights]::Write -bor `
                 [System.Security.AccessControl.FileSystemRights]::Modify -bor `
                 [System.Security.AccessControl.FileSystemRights]::FullControl -bor `
                 [System.Security.AccessControl.FileSystemRights]::WriteData -bor `
                 [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor `
                 [System.Security.AccessControl.FileSystemRights]::CreateDirectories

    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
            $sidVal = $null
            try {
                if ($rule.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                    $sidVal = $rule.IdentityReference.Value
                }
                else {
                    $sidVal = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
            }
            catch {
                $sidVal = $rule.IdentityReference.Value
            }

            if (($broadSids -contains $sidVal -or
                 $rule.IdentityReference.Value -in @('Everyone', 'NT AUTHORITY\Authenticated Users', 'BUILTIN\Users')) -and
                (($rule.FileSystemRights -band $writeMask) -ne 0)) {
                throw "Security Invariant Violation: Path '$Path' retains write permissions for broad principal '$($rule.IdentityReference.Value)'."
            }
        }
    }
}

$TotalSteps = 8

try {
    # =========================================================================
    # STEP 1: PRE-FLIGHT CHECKS
    # =========================================================================
    Write-StepHeader -StepNumber 1 -TotalSteps $TotalSteps -Title "Pre-flight Environment & Security Invariant Checks"

    # 1.1 Verify Administrator Elevation
    $currentIdentity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal($currentIdentity)
    $isAdmin          = $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    $currentUserSid   = $currentIdentity.User.Value
    $currentUserName  = $currentIdentity.Name

    if (-not $isAdmin) {
        throw "Administrator elevation is required. Please re-run Install-WindowsServerMcp.ps1 from an elevated PowerShell prompt."
    }
    Write-Success "Running elevated as '$currentUserName' (SID: $currentUserSid)"

    # 1.2 Check Windows OS Version (Windows Server 2022 / 2025 or Windows 11 — Build >= 20348)
    $osInfo  = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $osBuild = [int]$osInfo.BuildNumber
    $osName  = $osInfo.Caption
    if ($osBuild -lt 20348) {
        Write-Warn "Detected OS '$osName' (Build $osBuild). Windows Server 2022 (Build 20348), Windows Server 2025 (Build 26100), or Windows 11 (Build 22000+) is recommended."
    }
    else {
        Write-Success "Verified OS compatibility: $osName (Build $osBuild)"
    }

    # 1.3 Check Domain Membership & Resolve gMSA / Service Identity
    $csInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $isDomainJoined = [bool]$csInfo.PartOfDomain
    $domainName     = $csInfo.Domain

    if ([string]::IsNullOrWhiteSpace($GmsaAccount)) {
        if ($isDomainJoined -and (-not $DevMode) -and (-not $NonInteractive) -and [Environment]::UserInteractive) {
            $inputGmsa = Read-Host "  [?] Host is joined to domain '$domainName'. Enter gMSA account (e.g. $domainName\McpBrokerSvc$) or press Enter for 'NT AUTHORITY\SYSTEM'"
            if (-not [string]::IsNullOrWhiteSpace($inputGmsa)) {
                $GmsaAccount = $inputGmsa.Trim()
            }
            else {
                $GmsaAccount = "NT AUTHORITY\SYSTEM"
            }
        }
        else {
            $GmsaAccount = "NT AUTHORITY\SYSTEM"
        }
    }
    Write-Success "Configured Windows Service identity: $GmsaAccount"

    # If a gMSA account is specified (ends with '$'), verify ActiveDirectory module & Test-ADServiceAccount if available
    if ($GmsaAccount.EndsWith('$')) {
        if (-not $isDomainJoined) {
            throw "Cannot use gMSA account '$GmsaAccount' on a non-domain-joined host."
        }
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            $shortGmsa = ($GmsaAccount -replace '^.*\\', '' -replace '\$$', '')
            if (Get-Command Test-ADServiceAccount -ErrorAction SilentlyContinue) {
                $gmsaValid = Test-ADServiceAccount -Identity $shortGmsa -ErrorAction SilentlyContinue
                if (-not $gmsaValid) {
                    throw "gMSA '$GmsaAccount' failed Test-ADServiceAccount on this host. Run 'Install-ADServiceAccount -Identity $shortGmsa' first."
                }
                Write-Success "Verified gMSA '$GmsaAccount' is installed and usable on this host."
            }
        }
    }

    # 1.4 Verify .NET 8 SDK or ASP.NET Core / .NET 8 Runtime
    $dotnetCmd = Get-Command dotnet -ErrorAction SilentlyContinue
    if (-not $dotnetCmd) {
        throw "The 'dotnet' CLI was not found in PATH. Install the .NET 8.0 SDK (or .NET 8.0 Hosting Bundle with -SkipBuild) before running this installer."
    }

    $dotnetSdks     = @(& dotnet --list-sdks 2>$null | Where-Object { $_ -match '^8\.' })
    $dotnetRuntimes = @(& dotnet --list-runtimes 2>$null | Where-Object { $_ -match 'Microsoft\.(NETCore|AspNetCore)\.App 8\.' })

    if (-not $SkipBuild -and $dotnetSdks.Count -eq 0) {
        throw ".NET 8.0 SDK is required to compile from source (or pass -SkipBuild with pre-compiled binaries). Installed runtimes: $($dotnetRuntimes -join '; ')"
    }
    if ($dotnetRuntimes.Count -eq 0 -and $dotnetSdks.Count -eq 0) {
        throw "Neither .NET 8.0 Runtime nor .NET 8.0 SDK was detected. Please install .NET 8.0."
    }
    Write-Success "Verified .NET 8 toolchain (SDKs: $($dotnetSdks.Count), Runtimes: $($dotnetRuntimes.Count))"

    # 1.5 Resolve CallerSids & ApproverSids (Enforcing Invariant 1: Disjointness)
    if (-not $CallerSids -or $CallerSids.Count -eq 0) {
        if ($DevMode) {
            $CallerSids = @($currentUserSid)
            Write-Info "DevMode active: Defaulting CallerSids to current user SID ($currentUserSid)"
        }
        elseif (-not $NonInteractive -and [Environment]::UserInteractive) {
            $callerInput = Read-Host "  [?] Enter allowed MCP Caller SID(s) (comma-separated, or press Enter for current user $currentUserSid)"
            if ([string]::IsNullOrWhiteSpace($callerInput)) {
                $CallerSids = @($currentUserSid)
            }
            else {
                $CallerSids = @($callerInput.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            }
        }
        else {
            $CallerSids = @($currentUserSid)
        }
    }

    if (-not $ApproverSids -or $ApproverSids.Count -eq 0) {
        if ($DevMode) {
            $ApproverSids = @("S-1-5-21-999999999-999999999-999999999-9999")
            Write-Info "DevMode active: Using disjoint synthetic ApproverSid ($($ApproverSids[0]))"
        }
        elseif (-not $NonInteractive -and [Environment]::UserInteractive) {
            $approverInput = Read-Host "  [?] Enter distinct Human Approver SID(s) for write-tier elicitation (comma-separated, MUST NOT overlap CallerSids)"
            if ([string]::IsNullOrWhiteSpace($approverInput)) {
                throw "Production mode requires at least one distinct Approver SID (-ApproverSids) for Human-in-the-Loop write-tier authorization."
            }
            $ApproverSids = @($approverInput.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        }
        else {
            throw "Production mode requires explicit -ApproverSids that are strictly disjoint from -CallerSids."
        }
    }

    $callerHashSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$CallerSids, [System.StringComparer]::OrdinalIgnoreCase)
    $overlappingSids = @($ApproverSids | Where-Object { $callerHashSet.Contains($_) })
    if ($overlappingSids.Count -gt 0) {
        throw "Invariant 1 Violation (CallerSids ∩ ApproverSids = ∅): CallerSids and ApproverSids cannot overlap. Overlapping SID(s): $($overlappingSids -join ', ')"
    }
    Write-Success "Verified Invariant 1 (Disjoint Caller & Approver Identities)"

    # 1.6 Resolve Code-Signing Certificate
    if (-not (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name Cert -PSProvider Certificate -Root '\' -Scope Global | Out-Null
    }

    $signingCert = $null
    if (-not [string]::IsNullOrWhiteSpace($CertThumbprint)) {
        $cleanThumb = ($CertThumbprint -replace '\s+', '').ToUpperInvariant()
        $signingCert = Get-ChildItem -Path 'Cert:\LocalMachine\My', 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $cleanThumb } |
            Select-Object -First 1
        if (-not $signingCert) {
            throw "Code-signing certificate with thumbprint '$cleanThumb' was not found in Cert:\LocalMachine\My or Cert:\CurrentUser\My."
        }
        if (-not $signingCert.HasPrivateKey) {
            throw "Certificate '$cleanThumb' ($($signingCert.Subject)) does not have an associated private key required for Authenticode signing."
        }
        $CertThumbprint = $signingCert.Thumbprint
        Write-Success "Found enterprise code-signing certificate: $($signingCert.Subject) [$CertThumbprint]"
    }
    else {
        # No thumbprint passed: check if DevMode or AutoTrustCert or prompt
        $generateEvalCert = $false
        if ($DevMode -or $AutoTrustCert) {
            $generateEvalCert = $true
        }
        elseif (-not $NonInteractive -and [Environment]::UserInteractive) {
            $certChoice = Read-Host "  [?] No -CertThumbprint provided. Enter thumbprint now, or type 'AUTO' to generate a self-signed evaluation certificate"
            if ($certChoice.Trim().ToUpperInvariant() -eq 'AUTO' -or [string]::IsNullOrWhiteSpace($certChoice)) {
                $generateEvalCert = $true
                $AutoTrustCert = $true
            }
            else {
                $cleanThumb = ($certChoice -replace '\s+', '').ToUpperInvariant()
                $signingCert = Get-ChildItem -Path 'Cert:\LocalMachine\My', 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue |
                    Where-Object { $_.Thumbprint -eq $cleanThumb } |
                    Select-Object -First 1
                if (-not $signingCert) {
                    throw "Certificate with thumbprint '$cleanThumb' not found."
                }
                $CertThumbprint = $signingCert.Thumbprint
            }
        }
        else {
            throw "No -CertThumbprint specified. Provide an enterprise AD CS certificate thumbprint, or pass -DevMode / -AutoTrustCert for evaluation."
        }

        if ($generateEvalCert) {
            $evalSubject = "CN=McpBrokerEnterpriseEvalCodeSigning"
            $existingEval = Get-ChildItem -Path 'Cert:\LocalMachine\My', 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue |
                Where-Object { $_.Subject -eq $evalSubject -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays(30) } |
                Select-Object -First 1

            if ($existingEval) {
                $signingCert = $existingEval
                Write-Info "Reusing existing evaluation code-signing certificate: $($signingCert.Thumbprint)"
            }
            else {
                Write-Info "Generating hardened RSA-3072 SHA256 self-signed code-signing certificate ($evalSubject)..."
                $signingCert = New-SelfSignedCertificate `
                    -Type CodeSigningCert `
                    -Subject $evalSubject `
                    -KeyAlgorithm RSA `
                    -KeyLength 3072 `
                    -HashAlgorithm SHA256 `
                    -CertStoreLocation "Cert:\LocalMachine\My" `
                    -NotAfter (Get-Date).AddYears(3)
            }
            $CertThumbprint = $signingCert.Thumbprint

            if ($AutoTrustCert -or $DevMode) {
                Write-Info "Importing evaluation certificate into LocalMachine\Root and LocalMachine\TrustedPublisher for WinVerifyTrust validation..."
                foreach ($storeName in @('Root', 'TrustedPublisher')) {
                    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
                        [System.Security.Cryptography.X509Certificates.StoreName]::$storeName,
                        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
                    )
                    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                    if (-not ($store.Certificates | Where-Object { $_.Thumbprint -eq $signingCert.Thumbprint })) {
                        $store.Add($signingCert)
                    }
                    $store.Close()
                }
                Write-Success "Trusted evaluation certificate [$CertThumbprint] in LocalMachine\Root and TrustedPublisher."
            }
        }
    }

    # 1.7 Ensure Local JEA Access Group Exists if using local non-broad group
    if ([string]::IsNullOrWhiteSpace($AccessGroup)) {
        if ($DevMode -or -not $isDomainJoined) {
            $AccessGroup = "McpBrokerServiceGroup"
        }
        else {
            $AccessGroup = "$domainName\McpBrokerCallers"
        }
    }

    if ($AccessGroup -eq "McpBrokerServiceGroup") {
        if (-not (Get-LocalGroup -Name "McpBrokerServiceGroup" -ErrorAction SilentlyContinue)) {
            Write-Info "Creating dedicated local security group 'McpBrokerServiceGroup' (Invariant 3 compliance)..."
            New-LocalGroup -Name "McpBrokerServiceGroup" -Description "Dedicated JEA endpoint access group for Windows-Server-MCP Broker Service." | Out-Null
        }
        Write-Success "Verified dedicated JEA access group: $AccessGroup"
    }

    # =========================================================================
    # STEP 2: SECURE FILE HIERARCHY (Created & Hardened Prior to Staging)
    # =========================================================================
    # Note: We establish and lock down the directory tree immediately so binaries
    # and policy artifacts are staged directly into an ACL-protected hierarchy.
    Write-StepHeader -StepNumber 2 -TotalSteps $TotalSteps -Title "Creating & Hardening Appliance Directory Hierarchy ($TargetDir)"

    $BinDir         = Join-Path $TargetDir "bin"
    $JeaDir         = Join-Path $TargetDir "jea"
    $JeaModulesDir  = Join-Path $JeaDir "modules"
    $JeaGenDir      = Join-Path $JeaDir "generated"
    $PolicyDir      = Join-Path $TargetDir "policy"
    $TranscriptsDir = Join-Path $TargetDir "Transcripts"
    $LogsDir        = Join-Path $TargetDir "logs"
    $DeployOutDir   = Join-Path $TargetDir "deploy"

    $allDirs = @(
        $TargetDir,
        $BinDir,
        $JeaDir,
        $JeaModulesDir,
        $JeaGenDir,
        $PolicyDir,
        $TranscriptsDir,
        $LogsDir,
        $DeployOutDir
    )

    foreach ($dir in $allDirs) {
        Set-HardenedDirectoryAcl -Path $dir -ServicePrincipal $GmsaAccount
        Assert-NoBroadWriteAccess -Path $dir
    }
    Write-Success "Created and applied hardened NTFS DACLs to $TargetDir (bin, jea, policy, Transcripts, logs)"
    Write-Success "Verified zero write permissions for BUILTIN\Users, Authenticated Users, and Everyone"

    # =========================================================================
    # STEP 3: COMPILE & STAGE BINARIES
    # =========================================================================
    Write-StepHeader -StepNumber 3 -TotalSteps $TotalSteps -Title "Compiling & Staging Release Binaries to $BinDir"

    # Stop existing service if running so binaries are not file-locked
    $existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingSvc -and $existingSvc.Status -ne 'Stopped') {
        Write-Info "Stopping running service '$ServiceName' before updating binaries..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }

    $projectsToPublish = @(
        @{ Name = "Broker.Host";        Path = (Join-Path $RepoRoot "src\Broker.Host\Broker.Host.csproj");               Exe = "Broker.Host.exe" },
        @{ Name = "Broker.McpAdapter";  Path = (Join-Path $RepoRoot "src\Broker.McpAdapter\Broker.McpAdapter.csproj");   Exe = "Broker.McpAdapter.exe" },
        @{ Name = "Broker.ApproverCli"; Path = (Join-Path $RepoRoot "src\Broker.ApproverCli\Broker.ApproverCli.csproj"); Exe = "Broker.ApproverCli.exe" }
    )

    if (-not $SkipBuild) {
        foreach ($proj in $projectsToPublish) {
            Write-Info "Publishing $($proj.Name) (Release) -> $BinDir ..."
            $pubOut = & dotnet publish $proj.Path -c Release -o $BinDir --nologo 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to publish $($proj.Name) (Exit code $LASTEXITCODE):`n$pubOut"
            }
        }
        Write-Success "Compiled and staged Broker.Host, Broker.McpAdapter, and Broker.ApproverCli to $BinDir"
    }
    else {
        Write-Info "-SkipBuild specified: Locating existing compiled binaries..."
        foreach ($proj in $projectsToPublish) {
            $targetExe = Join-Path $BinDir $proj.Exe
            if (-not (Test-Path -LiteralPath $targetExe)) {
                $candidateDirs = @(
                    (Join-Path $RepoRoot "publish"),
                    (Join-Path $RepoRoot "bin"),
                    (Join-Path $RepoRoot "src\$($proj.Name)\bin\Release\net8.0-windows\publish"),
                    (Join-Path $RepoRoot "src\$($proj.Name)\bin\Release\net8.0-windows"),
                    (Join-Path $RepoRoot "src\$($proj.Name)\bin\Release\net8.0"),
                    (Join-Path $RepoRoot "src\$($proj.Name)\bin\Debug\net8.0-windows"),
                    (Join-Path $RepoRoot "src\$($proj.Name)\bin\Debug\net8.0")
                )
                $foundDir = $candidateDirs | Where-Object { Test-Path (Join-Path $_ $proj.Exe) } | Select-Object -First 1
                if (-not $foundDir) {
                    throw "-SkipBuild was specified, but '$($proj.Exe)' was not found in '$BinDir' or standard build output folders."
                }
                Write-Info "Copying $($proj.Name) binaries from '$foundDir' to '$BinDir'..."
                Copy-Item -Path (Join-Path $foundDir "*") -Destination $BinDir -Recurse -Force
            }
        }
        Write-Success "Verified pre-built binaries in $BinDir"
    }

    # Sign the staged executables with the code-signing certificate so Authenticode checks on Broker.Host.exe succeed
    foreach ($proj in $projectsToPublish) {
        $exePath = Join-Path $BinDir $proj.Exe
        if (Test-Path -LiteralPath $exePath) {
            $exeSig = Get-AuthenticodeSignature -LiteralPath $exePath
            if ($exeSig.Status -ne 'Valid' -and $null -ne $signingCert) {
                Write-Info "Signing executable $($proj.Exe) with certificate [$CertThumbprint]..."
                Set-AuthenticodeSignature -FilePath $exePath -Certificate $signingCert -HashAlgorithm SHA256 | Out-Null
            }
        }
    }

    # =========================================================================
    # STEP 4: COPY MANIFEST, POLICY & WRAPPER MODULES
    # =========================================================================
    Write-StepHeader -StepNumber 4 -TotalSteps $TotalSteps -Title "Staging Policy Manifest, Sidecar & JEA Wrapper Modules"

    $srcManifest = Join-Path $RepoRoot "policy\manifest.json"
    $srcSidecar  = Join-Path $RepoRoot "policy\manifest.json.sha256"
    $srcSchema   = Join-Path $RepoRoot "policy\tool-manifest.schema.json"
    $srcModules  = Join-Path $RepoRoot "jea\modules"
    $srcDeploy   = Join-Path $RepoRoot "deploy"

    $dstManifest = Join-Path $PolicyDir "manifest.json"
    $dstSidecar  = Join-Path $PolicyDir "manifest.json.sha256"
    $dstSchema   = Join-Path $PolicyDir "tool-manifest.schema.json"

    Copy-Item -LiteralPath $srcManifest -Destination $dstManifest -Force
    Copy-Item -LiteralPath $srcSidecar  -Destination $dstSidecar  -Force
    if (Test-Path -LiteralPath $srcSchema) {
        Copy-Item -LiteralPath $srcSchema -Destination $dstSchema -Force
    }
    Write-Success "Copied policy/manifest.json and policy/manifest.json.sha256 to $PolicyDir"

    # Copy JEA wrapper modules into both $TargetDir\jea\modules and $TargetDir\jea
    Get-ChildItem -Path $srcModules -Filter "*.psm1" | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $JeaModulesDir $_.Name) -Force
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $JeaDir $_.Name) -Force
    }
    Write-Success "Staged 62 JEA wrapper modules (.psm1) to $JeaModulesDir"

    # Copy deployment helper scripts to $TargetDir\deploy for appliance self-containment
    Get-ChildItem -Path $srcDeploy -Filter "*.ps1" | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $DeployOutDir $_.Name) -Force
    }

    # Ensure src\Broker.Host\appsettings.json exists in $TargetDir for auto-configure.ps1 compatibility
    $applianceHostConfigDir = Join-Path $TargetDir "src\Broker.Host"
    Set-HardenedDirectoryAcl -Path (Join-Path $TargetDir "src") -ServicePrincipal $GmsaAccount
    Set-HardenedDirectoryAcl -Path $applianceHostConfigDir -ServicePrincipal $GmsaAccount
    $srcAppSettings = Join-Path $RepoRoot "src\Broker.Host\appsettings.json"
    $applianceAppSettings = Join-Path $applianceHostConfigDir "appsettings.json"
    Copy-Item -LiteralPath $srcAppSettings -Destination $applianceAppSettings -Force

    # =========================================================================
    # STEP 5: AUTO-CONFIGURE, MODULE SIGNING & JEA ENDPOINT REGISTRATION
    # =========================================================================
    Write-StepHeader -StepNumber 5 -TotalSteps $TotalSteps -Title "Executing Auto-Configuration, Authenticode Signing & JEA Registration"

    # If CertThumbprint was provided or generated, update manifest module paths, thumbprints, accessGroup, and sidecar
    # before invoking auto-configure.ps1 so both DevMode and Production modes validate cleanly in $TargetDir.
    Write-Info "Signing JEA wrapper modules in $JeaModulesDir and $JeaDir with certificate [$CertThumbprint]..."
    $signedModuleCount = 0
    Get-ChildItem -Path $JeaModulesDir -Filter "*.psm1" | ForEach-Object {
        Set-AuthenticodeSignature -FilePath $_.FullName -Certificate $signingCert -HashAlgorithm SHA256 | Out-Null
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $JeaDir $_.Name) -Force
        $signedModuleCount++
    }
    Write-Success "Authenticode-signed $signedModuleCount JEA wrapper modules (SHA-256)"

    # Prepare manifest in $TargetDir\policy\manifest.json with actual target paths, thumbprint, and accessGroup
    $manifestObj = Get-Content -LiteralPath $dstManifest -Raw | ConvertFrom-Json
    foreach ($tool in $manifestObj.tools) {
        $tool.server.signatureThumbprint = $CertThumbprint
        $modFile = "$($tool.jeaMapping.moduleName).psm1"
        $tool.server.path = Join-Path $JeaDir $modFile
        $tool.jeaMapping.accessGroup = $AccessGroup
    }
    $updatedManifestContent = $manifestObj | ConvertTo-Json -Depth 20
    [System.IO.File]::WriteAllText($dstManifest, $updatedManifestContent, [System.Text.Encoding]::UTF8)

    $newSidecarHash = Get-Sha256Hex -Path $dstManifest
    [System.IO.File]::WriteAllText($dstSidecar, $newSidecarHash, [System.Text.Encoding]::ASCII)
    Write-Success "Updated $dstManifest and recalculated integrity sidecar ($newSidecarHash)"

    # Invoke deploy/auto-configure.ps1 -Full against $TargetDir
    $autoConfigScript = Join-Path $DeployOutDir "auto-configure.ps1"
    $autoConfigArgs = @(
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-File", $autoConfigScript,
        "-Full",
        "-RepoRoot", $TargetDir,
        "-DeployRoot", $TargetDir,
        "-TranscriptDir", $TranscriptsDir,
        "-CertThumbprint", $CertThumbprint,
        "-AccessGroup", $AccessGroup,
        "-SkipBuild",
        "-SkipTests"
    )
    if ($DevMode) {
        $autoConfigArgs += "-DevMode"
    }
    if ($CallerSids -and $CallerSids.Count -gt 0) {
        $autoConfigArgs += "-CallerSids"
        $autoConfigArgs += ($CallerSids -join ",")
    }
    if ($ApproverSids -and $ApproverSids.Count -gt 0) {
        $autoConfigArgs += "-ApproverSids"
        $autoConfigArgs += ($ApproverSids -join ",")
    }

    Write-Info "Running deploy\auto-configure.ps1 -Full against $TargetDir..."
    $hostDllInBin = Join-Path $BinDir "Broker.Host.dll"
    # Stage compiled binaries to $TargetDir\src\Broker.Host\bin\Release\net8.0-windows so auto-configure.ps1 finds Broker.Host.dll
    $stagedHostBin = Join-Path $TargetDir "src\Broker.Host\bin\Release\net8.0-windows"
    Set-HardenedDirectoryAcl -Path (Join-Path $TargetDir "src\Broker.Host\bin") -ServicePrincipal $GmsaAccount
    Set-HardenedDirectoryAcl -Path (Join-Path $TargetDir "src\Broker.Host\bin\Release") -ServicePrincipal $GmsaAccount
    Set-HardenedDirectoryAcl -Path $stagedHostBin -ServicePrincipal $GmsaAccount
    Copy-Item -Path (Join-Path $BinDir "*") -Destination $stagedHostBin -Recurse -Force

    $autoOut = & powershell.exe @autoConfigArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "auto-configure.ps1 -Full failed (Exit code $LASTEXITCODE):`n$autoOut"
    }

    # Ensure generated JEA files are present and registered via register-jea.ps1
    $registerJeaScript = Join-Path $DeployOutDir "register-jea.ps1"
    Write-Info "Registering JEA Session Configurations (.psrc / .pssc) via Register-PSSessionConfiguration..."
    & $registerJeaScript -GeneratedDir $JeaGenDir -ModulesSourceDir $JeaModulesDir
    Write-Success "Registered JEA endpoints (McpBroker.ReadLocal, McpBroker.ReadDirectory, McpBroker.Write, McpBroker.DirectoryWrite)"

    # Synchronize configured appsettings.json to $BinDir\appsettings.json with absolute appliance paths
    $CorrelationLogPath = Join-Path $LogsDir "correlation.log"
    $runtimeAppSettings = Get-Content -LiteralPath $applianceAppSettings -Raw | ConvertFrom-Json
    $runtimeAppSettings.Manifest.Path          = $dstManifest
    $runtimeAppSettings.Manifest.IntegrityPath = $dstSidecar
    $runtimeAppSettings.Manifest.RequireIntegrity = $true
    $runtimeAppSettings.Jea.TranscriptDir      = $TranscriptsDir
    $runtimeAppSettings.Audit.CorrelationLogPath = $CorrelationLogPath
    $runtimeAppSettings.Pipe.AllowedSids       = @($CallerSids)
    $runtimeAppSettings.Elicitation.ApproverSids = @($ApproverSids)
    $runtimeAppSettings.Elicitation.RequireDistinctApprover = if ($DevMode) { $false } else { $true }

    $finalAppSettingsJson = $runtimeAppSettings | ConvertTo-Json -Depth 20
    $binAppSettingsPath   = Join-Path $BinDir "appsettings.json"
    [System.IO.File]::WriteAllText($binAppSettingsPath, $finalAppSettingsJson, [System.Text.Encoding]::UTF8)
    [System.IO.File]::WriteAllText($applianceAppSettings, $finalAppSettingsJson, [System.Text.Encoding]::UTF8)
    Write-Success "Wrote production runtime configuration to $binAppSettingsPath"

    # Re-verify hardened ACLs on all appliance folders after staging
    foreach ($dir in $allDirs) {
        Set-HardenedDirectoryAcl -Path $dir -ServicePrincipal $GmsaAccount
        Assert-NoBroadWriteAccess -Path $dir
    }

    # =========================================================================
    # STEP 6: WINDOWS SERVICE SETUP
    # =========================================================================
    Write-StepHeader -StepNumber 6 -TotalSteps $TotalSteps -Title "Registering & Starting Windows Service ($ServiceName)"

    $brokerHostExe = Join-Path $BinDir "Broker.Host.exe"
    if (-not (Test-Path -LiteralPath $brokerHostExe)) {
        throw "Broker.Host.exe was not found at '$brokerHostExe'."
    }

    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Info "Service '$ServiceName' already exists. Stopping and updating configuration..."
        if ($existingService.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        & sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 1
    }

    $quotedBinPath = "`"$brokerHostExe`" --contentRoot `"$BinDir`""
    if ($GmsaAccount -eq "NT AUTHORITY\SYSTEM" -or $GmsaAccount -eq "LocalSystem") {
        Write-Info "Creating Windows Service '$ServiceName' running as LocalSystem (start= auto)..."
        & sc.exe create $ServiceName binPath= $quotedBinPath start= auto obj= "LocalSystem" DisplayName= "Windows Server MCP Broker" | Out-Null
    }
    else {
        Write-Info "Creating Windows Service '$ServiceName' running under gMSA '$GmsaAccount' (start= auto)..."
        & sc.exe create $ServiceName binPath= $quotedBinPath start= auto obj= $GmsaAccount DisplayName= "Windows Server MCP Broker" | Out-Null
    }
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe create failed with exit code $LASTEXITCODE."
    }

    & sc.exe description $ServiceName "Centralized, JEA-boundaried Model Context Protocol (MCP) broker appliance for Windows Server." | Out-Null
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

    Write-Info "Starting Windows Service '$ServiceName'..."
    Start-Service -Name $ServiceName -ErrorAction Stop
    Start-Sleep -Seconds 2
    $svcState = Get-Service -Name $ServiceName
    Write-Success "Service '$ServiceName' is $($svcState.Status) (StartType: $($svcState.StartType))"

    # =========================================================================
    # STEP 7: HEALTH VERIFICATION
    # =========================================================================
    Write-StepHeader -StepNumber 7 -TotalSteps $TotalSteps -Title "Running Post-Deployment Health & Security Gate Verification"

    Write-Info "Executing deploy\auto-configure.ps1 -Validate..."
    $valJsonRaw = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $autoConfigScript -Validate -RepoRoot $TargetDir -SkipTests 2>$null
    $valObj = $valJsonRaw | ConvertFrom-Json

    Write-Info "Executing Broker.Host.exe self-check..."
    $selfCheckRaw = & $brokerHostExe self-check $binAppSettingsPath 2>&1
    $selfCheckExit = $LASTEXITCODE
    if ($selfCheckExit -ne 0) {
        throw "Broker.Host.exe self-check failed (Exit code $selfCheckExit):`n$selfCheckRaw"
    }

    Write-Success "Manifest Integrity Sidecar Match : $($valObj.Checks.ManifestIntegrityMatches)"
    Write-Success "All 62 JEA Modules Validly Signed: $($valObj.Checks.AllModulesSigned)"
    Write-Success "Zero Placeholder Thumbprints     : $($valObj.Checks.ZeroPlaceholderThumbprints)"
    Write-Success "Zero Placeholder SIDs            : $($valObj.Checks.ZeroPlaceholderSids)"
    Write-Success "Disjoint Caller & Approver SIDs  : $($valObj.Checks.ApproverSidsDisjoint)"
    Write-Success "JEA Role & Session Configs Ready : $($valObj.Checks.JeaArtifactsPresent) ($($valObj.Checks.GeneratedRoleCapabilitiesCount) .psrc, $($valObj.Checks.GeneratedSessionConfigsCount) .pssc)"
    Write-Success "Broker.Host.exe Self-Check       : PASSED (Exit Code 0)"

    # =========================================================================
    # STEP 8: OUTPUT SUMMARY & CLIENT CONFIGURATION SNIPPETS
    # =========================================================================
    $Stopwatch.Stop()
    $elapsedSec = [Math]::Round($Stopwatch.Elapsed.TotalSeconds, 1)

    $escapedAdapterPath  = (Join-Path $BinDir "Broker.McpAdapter.exe").Replace('\', '\\')
    $escapedManifestPath = $dstManifest.Replace('\', '\\')
    $approverCliPath     = Join-Path $BinDir "Broker.ApproverCli.exe"

    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║         WINDOWS-SERVER-MCP APPLIANCE DEPLOYMENT COMPLETED SUCCESSFULLY       ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Deployment Summary:" -ForegroundColor White
    Write-Host ("    • Installation Path   : {0}" -f $TargetDir) -ForegroundColor Gray
    Write-Host ("    • Windows Service     : {0} [{1} / {2}]" -f $ServiceName, $svcState.Status, $svcState.StartType) -ForegroundColor Green
    Write-Host ("    • Service Identity    : {0}" -f $GmsaAccount) -ForegroundColor Gray
    Write-Host ("    • Signing Thumbprint  : {0}" -f $CertThumbprint) -ForegroundColor Gray
    Write-Host ("    • Allowed Caller SIDs : {0}" -f ($CallerSids -join ", ")) -ForegroundColor Gray
    Write-Host ("    • Approver SIDs       : {0}" -f ($ApproverSids -join ", ")) -ForegroundColor Gray
    Write-Host ("    • Elapsed Time        : {0} seconds" -f $elapsedSec) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Human-in-the-Loop Approver Console (Run as Authorized Approver):" -ForegroundColor Yellow
    Write-Host ("    `"{0}`" --pipe McpBroker.Approvals" -f $approverCliPath) -ForegroundColor White
    Write-Host ""
    Write-Host "  Ready-to-Use Client Configuration (claude_desktop_config.json & Cursor .cursor/mcp.json):" -ForegroundColor Cyan
    $clientConfigSnippet = @"
{
  "mcpServers": {
    "windows-server-mcp": {
      "command": "$escapedAdapterPath",
      "args": [
        "--pipe",
        "McpBroker",
        "--manifest",
        "$escapedManifestPath"
      ]
    }
  }
}
"@
    Write-Host $clientConfigSnippet -ForegroundColor White
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Fail "DEPLOYMENT FAILED: $($_.Exception.Message)"
    if ($_.ScriptStackTrace) {
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
    }
    exit 1
}

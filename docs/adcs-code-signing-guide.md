# Enterprise CA Signing Guide & Active Directory Certificate Services (AD CS) Integration

## 1. Overview & Security Rationale

**Windows-Server-MCP** is a fail-closed Model Context Protocol (MCP) broker appliance engineered for Windows Server 2022 and Windows Server 2025. Unlike conventional agent wrappers that execute arbitrary shell commands, Windows-Server-MCP enforces **cryptographic provenance** and **OS-level permission boundaries** across every tool invocation.

### Why Authenticode Signatures Are Strictly Enforced

Every tool registered in `policy/manifest.json` maps to a hardened Just Enough Administration (JEA) wrapper module (`jea/modules/*.psm1`) and a constrained PowerShell session configuration (`.pssc`/`.psrc`). Before any tool request reaches a JEA runspace, the broker executes an **8-gate fail-closed pipeline**:

```
1. Manifest Lookup  -->  2. Rate Limit  -->  3. Authenticode Signature Re-Check (WinVerifyTrust)
   -->  3b. Caller Taint Check  -->  4. Parameter Allowlist  -->  5. AMSI Scan
   -->  6. Untrusted-Source Gate  -->  7. Human Elicitation  -->  8. JEA Invoke
```

At **Gate 3 (Signature Re-Check)** and during JEA endpoint registration (`deploy/register-jea.ps1`), the appliance enforces three cryptographic invariants:

1. **Real-Time `WinVerifyTrust` Verification**: On every call, `SignatureVerifier` invokes the native Windows `WinVerifyTrust` API (`WTD_CHOICE_FILE` with catalog fallback `WTD_CHOICE_CATALOG`) and `WTD_REVOCATION_CHECK_CHAIN` to verify that the target `.psm1` module and `Broker.Host.exe` carry a valid, unbroken Authenticode signature chaining to a root authority in `Cert:\LocalMachine\Root` and a trusted publisher in `Cert:\LocalMachine\TrustedPublisher`.
2. **Pinned Thumbprint Matching**: The signing certificate's SHA-1 thumbprint (`CertThumbprint`) must match the `server.signatureThumbprint` field pinned in `policy/manifest.json` (which is itself protected by the `policy/manifest.json.sha256` integrity sidecar and NTFS DACLs).
3. **PowerShell JEA & WDAC Enforcement**: All 62 JEA wrapper modules (`Get-Broker*.psm1` and `Set-Broker*.psm1`) execute under `RestrictedRemoteServer` and `NoLanguage` mode. When paired with Windows Defender Application Control (`deploy/setup-wdac.ps1`), the Windows kernel blocks any unsigned or tampered script from loading into memory—preventing privilege escalation, supply-chain tampering, or unauthorized wrapper modification even if an attacker gains local file access.

> **Production Mandate (Audit Finding C1)**: In Production mode, `deploy/auto-configure.ps1` and `deploy/Install-WindowsServerMcp.ps1` refuse to run without an enterprise CA code-signing certificate thumbprint (`-CertThumbprint`). Self-signed certificates are strictly restricted to isolated lab/evaluation environments (`-DevMode`).

---

## 2. AD CS Certificate Template Configuration (Step-by-Step)

To issue an enterprise-trusted Authenticode certificate for signing Windows-Server-MCP binaries and JEA wrapper modules, configure a dedicated Certificate Template on your Enterprise Certificate Authority running **Active Directory Certificate Services (AD CS)**.

### Step 2.1: Duplicate the Built-In Code Signing Template

1. Sign in to your Enterprise Issuing CA (or a management workstation with RSAT AD CS tools installed) as a member of **Domain Admins** or **Enterprise Admins**.
2. Open the **Certification Authority** console (`certsrv.msc`).
3. Expand your CA node, right-click **Certificate Templates**, and select **Manage** to open the **Certificate Templates Console** (`certtmpl.msc`).
4. Locate the built-in **Code Signing** template in the middle pane, right-click it, and click **Duplicate Template**.

### Step 2.2: Configure General & Compatibility Settings

1. **Compatibility Tab**:
   - **Certification Authority**: Select **Windows Server 2016** (or **Windows Server 2022 / 2025** if your forest functional level matches).
   - **Certificate recipient**: Select **Windows 10 / Windows Server 2016** or later.
2. **General Tab**:
   - **Template display name**: `MCP Broker Code Signing`
   - **Template name**: `McpBrokerCodeSigning` (no spaces; used by `Get-Certificate` and `certreq.exe`).
   - **Validity period**: `1 year` (or `2 years` per corporate PKI policy).
   - **Renewal period**: `6 weeks`.
   - Check **Publish certificate in Active Directory** if required by your PKI auditing standards.

### Step 2.3: Configure Request Handling & Cryptography

1. **Request Handling Tab**:
   - **Purpose**: `Signature`
   - **Allow private key to be exported**:
     - Leave **unchecked** if enrolling directly on the designated build/release host or target Windows Server appliance.
     - Check **Allow private key to be exported** *only* if you enroll on a central PKI workstation and export a password-protected `.pfx` to your CI/CD signing vault.
   - Select **Enroll subject without requiring any user input** (enables automated CLI/PowerShell enrollment).
2. **Cryptography Tab**:
   - **Provider Category**: `Key Storage Provider` (KSP).
   - **Algorithm name**: `RSA`
   - **Minimum key size**: `3072` (or `4096` for high-assurance environments).
   - **Providers**: Select **Microsoft Software Key Storage Provider** (or **Microsoft Platform Crypto Provider** for TPM-backed non-exportable keys).
   - **Request hash**: `SHA256`

### Step 2.4: Configure Subject Name

1. Navigate to the **Subject Name** tab and choose the option that matches your deployment model:
   - **Option A — Build from this Active Directory information (Recommended for AD Auto-Enrollment / Service Accounts)**:
     - Select **Build from this Active Directory information**.
     - **Subject name format**: `Common name`
     - Under **Include this information in alternate subject name**, check **User principal name (UPN)** or **DNS name** (if enrolling as computer/service identity).
   - **Option B — Supply in the request (Recommended for CI/CD Release Pipelines & Custom CNs)**:
     - Select **Supply in the request** so your `.inf` file can specify an explicit organizational subject such as `CN=Contoso MCP Broker Release Signer, O=Contoso Corporation, C=US`.
     - If selecting **Supply in the request**, ensure **CA certificate manager approval** is enabled on the **Issuance Requirements** tab or restrict **Enroll** permissions exclusively to your Release Engineering security group to prevent arbitrary subject spoofing (ESC1 mitigation).

### Step 2.5: Configure Extensions (Key Usage & Enhanced Key Usage)

1. Navigate to the **Extensions** tab:
2. Select **Application Policies** (and **Enhanced Key Usage**) and click **Edit**:
   - Verify that **Code Signing** (`OID: 1.3.6.1.5.5.7.3.3`) is present.
   - Remove any unrelated EKUs (such as `Client Authentication` or `Server Authentication`) so the certificate cannot be misused for TLS or Kerberos authentication.
3. Select **Key Usage** and click **Edit**:
   - Verify **Digital signature** is checked.
   - Check **Make this extension critical**.

### Step 2.6: Grant Security & Enrollment Permissions

1. Navigate to the **Security** tab:
2. Click **Add...** (ensure **Object Types** includes **Users, Groups, Service Accounts, or Computers**).
3. Add your designated deployment security group (e.g., `CONTOSO\McpBrokerDeployers`) or build server computer account.
4. With `CONTOSO\McpBrokerDeployers` selected, check **Allow** for:
   - **Read**
   - **Enroll**
   - **Autoenroll** (if configuring Group Policy auto-enrollment for a dedicated build server).
5. Ensure broad groups (`Domain Users`, `Authenticated Users`, `Domain Computers`) do **not** have **Enroll** or **Write** permissions.
6. Click **OK** to save the template.

### Step 2.7: Publish the Template on the Issuing CA

1. Return to the **Certification Authority** console (`certsrv.msc`).
2. Right-click **Certificate Templates** -> **New** -> **Certificate Template to Issue**.
3. Select **MCP Broker Code Signing (`McpBrokerCodeSigning`)** and click **OK**.

---

## 3. Enrolling and Exporting the Certificate

Once the `McpBrokerCodeSigning` template is published in Active Directory, enroll the certificate using either the native PowerShell PKI module or `certreq.exe`.

### Method A: Native PowerShell Enrollment (`Get-Certificate`)

When the template is configured with **Build from this Active Directory information**, enroll directly into the local machine certificate store from an elevated PowerShell session:

```powershell
# Enroll using the AD CS template name into Cert:\LocalMachine\My
$enrollment = Get-Certificate `
    -Template "McpBrokerCodeSigning" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -SubjectName "CN=Contoso MCP Broker Appliance Signer"

$cert = $enrollment.Certificate
Write-Host "Enrolled Certificate Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green

# Export the public certificate (.cer) for Group Policy distribution to Trusted Publishers
Export-Certificate `
    -Cert $cert `
    -FilePath "C:\McpBroker\McpBrokerCodeSigning.cer" `
    -Type CERT
```

### Method B: `certreq.exe` Workflow with Custom `.inf` Request File

When the template is configured with **Supply in the request** (or when enrolling from a release pipeline requiring an explicit Subject Name and KSP configuration), use `certreq.exe`:

#### 1. Create `mcp-codesign-request.inf`

```ini
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN=Contoso MCP Broker Release Signer, OU=Platform Security, O=Contoso Corporation, C=US"
KeySpec = 1
KeyLength = 3072
Exportable = FALSE
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft Software Key Storage Provider"
ProviderType = 1
RequestType = PKCS10
KeyUsage = 0x80 ; Digital Signature
HashAlgorithm = SHA256

[EnhancedKeyUsageExtension]
OID = 1.3.6.1.5.5.7.3.3 ; Code Signing

[RequestAttributes]
CertificateTemplate = "McpBrokerCodeSigning"
```

#### 2. Generate the CSR, Submit to AD CS, and Accept the Issued Certificate

```powershell
# 1. Generate the PKCS#10 request (.req) and private key in LocalMachine\My
certreq.exe -new .\mcp-codesign-request.inf .\mcp-codesign.req

# 2. Submit the request to your Enterprise Issuing CA (replace with your CA hostname\CAName)
certreq.exe -submit -config "ca01.contoso.com\Contoso-Enterprise-Issuing-CA" .\mcp-codesign.req .\mcp-codesign.cer

# 3. Accept and bind the issued certificate to the private key in Cert:\LocalMachine\My
certreq.exe -accept -machine .\mcp-codesign.cer

# 4. Retrieve the thumbprint for deployment
Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -like "*MCP Broker*" } |
    Select-Object Subject, Thumbprint, NotAfter, HasPrivateKey
```

---

## 4. Group Policy (GPO) Distribution Across Managed Servers

For `WinVerifyTrust`, PowerShell `AllSigned`/`RemoteSigned`, JEA, and WDAC to trust your signed JEA wrapper modules across every Windows Server running Windows-Server-MCP, two trust anchors must be present on all target servers:

1. **Enterprise Root CA (& Issuing Subordinate CA)** in `Cert:\LocalMachine\Root` (and `Cert:\LocalMachine\CA`).
2. **MCP Broker Code Signing Public Certificate (`.cer`)** in `Cert:\LocalMachine\TrustedPublisher`.

### Step 4.1: Distribute Enterprise Root CA to Trusted Root Certification Authorities

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a domain controller or management workstation.
2. Create or edit a GPO linked to the Organizational Unit (OU) containing your Windows Server MCP hosts (e.g., `OU=MCP-Managed-Servers,DC=contoso,DC=com`).
3. Navigate to:
   `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Public Key Policies -> Trusted Root Certification Authorities`
4. Right-click **Trusted Root Certification Authorities** -> **Import...** and import your Enterprise Root CA `.cer` file.
5. *(If using a 2-tier PKI)* Right-click **Intermediate Certification Authorities** -> **Import...** and import your Issuing Subordinate CA `.cer` file.

### Step 4.2: Distribute the Code Signing Certificate to Trusted Publishers

1. Within the same GPO, navigate to:
   `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Public Key Policies -> Trusted Publishers`
2. Right-click **Trusted Publishers** -> **Import...**
3. Select the public `McpBrokerCodeSigning.cer` exported in Section 3 (contains **only** the public key, never the `.pfx` private key).
4. Complete the wizard and click **Finish**.

### Step 4.3: Enable Certificate Services Client Auto-Enrollment (Optional)

If each managed Windows Server auto-enrolls its own certificates via GPO:

1. Navigate to:
   `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Public Key Policies`
2. Double-click **Certificate Services Client - Auto-Enrollment**.
3. Set **Configuration Model** to **Enabled**.
4. Check:
   - **Renew expired certificates, update pending certificates, and remove revoked certificates**
   - **Update certificates that use certificate templates**
5. Click **OK**, then run `gpupdate /force` on the target Windows Server and verify trust store population:

```powershell
gpupdate /force

# Confirm the Code Signing certificate is present in LocalMachine\TrustedPublisher
Get-ChildItem Cert:\LocalMachine\TrustedPublisher |
    Select-Object Subject, Thumbprint, Issuer, NotAfter
```

---

## 5. Signing the JEA Wrapper Modules

All 62 JEA wrapper modules (`C:\McpBroker\jea\modules\*.psm1`) and the broker host binaries must carry a valid SHA-256 Authenticode signature before JEA endpoint registration (`deploy/register-jea.ps1`) or service startup.

### PowerShell Signing Script (with RFC 3161 Timestamping)

Replace `<THUMBPRINT>` with your 40-character hexadecimal certificate thumbprint:

```powershell
$cert = Get-Item "Cert:\LocalMachine\My\<THUMBPRINT>"
Get-ChildItem -Path "C:\McpBroker\jea\modules\*.psm1" | ForEach-Object {
    Set-AuthenticodeSignature -FilePath $_.FullName -Certificate $cert -HashAlgorithm SHA256 -TimestampServer "http://timestamp.digicert.com"
}
```

> **Air-Gapped / Restricted Network Note**: If your Windows Server is deployed in an isolated Tier-0/Tier-1 datacenter VLAN without outbound HTTP access to `http://timestamp.digicert.com`, omit the `-TimestampServer` parameter (or point it to your internal RFC 3161 TSA responder). Both `Install-WindowsServerMcp.ps1` and `auto-configure.ps1` sign cleanly without requiring external internet access.

### Verifying All Module Signatures

Run the following verification command to confirm that every `.psm1` module reports `Status == Valid`:

```powershell
$invalid = Get-ChildItem -Path "C:\McpBroker\jea\modules\*.psm1" |
    ForEach-Object { Get-AuthenticodeSignature -FilePath $_.FullName } |
    Where-Object { $_.Status -ne 'Valid' }

if ($invalid) {
    Write-Error "Found $($invalid.Count) unsigned or invalidly signed JEA wrapper modules!"
    $invalid | Format-Table Path, Status, StatusMessage -AutoSize
} else {
    Write-Host "All 62 JEA wrapper modules carry valid Authenticode signatures." -ForegroundColor Green
}
```

---

## 6. Integration with `Install-WindowsServerMcp.ps1` & `auto-configure.ps1`

Once your AD CS certificate is enrolled in `Cert:\LocalMachine\My` (or `Cert:\CurrentUser\My`) and trusted in `Cert:\LocalMachine\TrustedPublisher`, pass its thumbprint directly via `-CertThumbprint`.

### Option A: One-Click Turn-Key Appliance Installer (`deploy/Install-WindowsServerMcp.ps1`)

`Install-WindowsServerMcp.ps1` automates building, NTFS ACL lockdown, module signing, manifest thumbprint pinning, SHA-256 sidecar calculation, JEA registration, Windows Service creation, and health validation in a single command:

```powershell
# Run from an elevated PowerShell prompt on the target Windows Server
.\deploy\Install-WindowsServerMcp.ps1 `
    -TargetDir "C:\McpBroker" `
    -ServiceName "McpBroker" `
    -GmsaAccount "CONTOSO\McpBrokerSvc$" `
    -CertThumbprint "4F8B9C1D2E3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C" `
    -CallerSids @("S-1-5-21-1286530945-682254993-2698348803-2105") `
    -ApproverSids @("S-1-5-21-1286530945-682254993-2698348803-5120")
```

### Option B: Granular AI / CI-CD Auto-Configuration Engine (`deploy/auto-configure.ps1`)

When integrating into an off-host CI/CD pipeline (Azure DevOps, GitHub Actions, or Ansible) where `manifest.json` and `manifest.json.sha256` are prepared prior to deployment:

```powershell
# 1. Generate a Production configuration profile bound to your AD CS certificate thumbprint
powershell -ExecutionPolicy Bypass -File .\deploy\auto-configure.ps1 `
    -Plan `
    -CertThumbprint "4F8B9C1D2E3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C" `
    -CallerSids "S-1-5-21-1286530945-682254993-2698348803-2105" `
    -ApproverSids "S-1-5-21-1286530945-682254993-2698348803-5120" `
    -AccessGroup "CONTOSO\McpBrokerCallers" `
    -ProfilePath .\deploy\broker-profile.json

# 2. Apply the profile (signs all 62 .psm1 modules, verifies sidecar, generates JEA .psrc/.pssc, registers JEA)
powershell -ExecutionPolicy Bypass -File .\deploy\auto-configure.ps1 `
    -Apply `
    -ProfilePath .\deploy\broker-profile.json

# 3. Validate all 7 health checks and run unit/self-check diagnostics
powershell -ExecutionPolicy Bypass -File .\deploy\auto-configure.ps1 -Validate
```

---

## 7. Evaluation / Lab Mode Fallback (Self-Signed Certificate)

For isolated lab, sandbox, or evaluation environments without an Active Directory Certificate Services (AD CS) hierarchy, you can either pass `-DevMode -AutoTrustCert` to `Install-WindowsServerMcp.ps1` or run the standalone PowerShell snippet below to generate a hardened RSA-3072 SHA-256 self-signed code-signing certificate and trust it locally.

> **WARNING**: Never import self-signed certificates into `LocalMachine\Root` or `LocalMachine\TrustedPublisher` on production domain controllers or production tier-1 servers. Remove evaluation certificates immediately after lab testing concludes.

### Standalone Hardened Self-Signed Certificate Generator & Trust Script

```powershell
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$CertSubject = "CN=McpBrokerLabEvalCodeSigning"

Write-Host "[1/4] Generating RSA-3072 SHA-256 Self-Signed Code Signing Certificate..." -ForegroundColor Cyan
$evalCert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $CertSubject `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -KeyExportPolicy NonExportable `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -NotAfter (Get-Date).AddYears(1)

$thumbprint = $evalCert.Thumbprint
Write-Host "      Created Certificate Thumbprint: $thumbprint" -ForegroundColor Green

Write-Host "[2/4] Exporting Public Certificate (.cer)..." -ForegroundColor Cyan
$cerPath = Join-Path $env:TEMP "McpBrokerLabEvalCodeSigning.cer"
Export-Certificate -Cert $evalCert -FilePath $cerPath -Force | Out-Null

Write-Host "[3/4] Importing into Cert:\LocalMachine\Root and Cert:\LocalMachine\TrustedPublisher..." -ForegroundColor Cyan
Import-Certificate -FilePath $cerPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
Import-Certificate -FilePath $cerPath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
Remove-Item -LiteralPath $cerPath -Force -ErrorAction SilentlyContinue

Write-Host "[4/4] Ready for Lab Deployment! Run the installer with:" -ForegroundColor Green
Write-Host "      .\deploy\Install-WindowsServerMcp.ps1 -DevMode -CertThumbprint `"$thumbprint`"" -ForegroundColor White
```

# MCP Broker — native-grade MCP package interface for Windows Server 2025

A centralized broker that is the single entry point for all MCP tool calls. Every call
lands on a permission boundary the OS enforces (named-pipe ACL + JEA), not an
application-level check. Built because Microsoft's native MCP stack is Windows 11 only.

## Five layers

1. **Broker service** (`Broker.Host`, `Broker.Transport`) — .NET 8 Worker Service, runs as
   a gMSA, exposes an ACL/SID-restricted named pipe. All clients connect here.
2. **Registry & trust** (`Broker.Registry`) — local signed manifest of backend servers,
   Authenticode thumbprint re-verification at call time, hot-reload revocation. WDAC
   restricts which binaries may execute at all (`deploy/setup-wdac.ps1`).
3. **Policy & consent** (`Broker.Policy`) — risk-tiered allowlist (read/write/destructive),
   per-parameter allowlist validation, untrusted-source gate, rate limiting, argv-only
   command construction, single-use MCP elicitation for write/destructive.
4. **JEA execution** (`Broker.JeaExecution`) — each tool maps to a JEA session config; the
   generator emits `.psrc`/`.pssc` with native `ValidateSet`/`ValidatePattern`/`ValidateRange`
   constraints, `NoLanguage` + `RestrictedRemoteServer`, virtual-account or gMSA identity,
   full transcription. The broker invokes through the JEA endpoint, never cmdlets directly.
5. **Audit** (`Broker.Audit`) — structured ETW events (request / elicitation / completion /
   reject / rate-limit) correlated to JEA transcripts by an injected correlation marker.

## Call pipeline (fail-closed, fixed order)

```
1 manifest lookup  ->  2 rate limit  ->  3 signature re-check  ->  3b caller taint
   ->  4 parameter allowlist  ->  AMSI  ->  5 untrusted-source gate  ->  7 elicitation  ->  8 JEA invoke
```

Any gate that does not explicitly allow terminates the call. Rate limiting runs
second (before expensive Authenticode signature checks) for DoS resistance. The
untrusted-source gate is a hard stop with no elicitation override: data that may
carry injected content (AD attributes, file contents, network responses) can
never reach a write/destructive tool.

## Security principles

- **Monotonic risk tiers & human elicitation** — 49 read tools for state query,
  13 write tools for state modification. Mutating (write-tier) tools strictly
  require interactive human approval from a distinct approver identity
  (`requiresElicitation: true`); approval can never be bypassed or downgraded.
  Destructive tier remains empty / generate-script only.
- **Rate-limit before crypto** — rate limiting runs second (before expensive
  WinVerifyTrust checks) to protect against CPU/IO exhaustion DoS.
- **No credentials in LLM context** — execution uses the gMSA's Kerberos identity
  or low-privilege virtual accounts.
- **Prompt-injection defense** — untrusted external data taints the caller and
  never auto-triggers a mutating tool.
- **Fail-closed masking** — sensitive output fields (SIDs, DNs) are redacted
  before return; non-JSON payloads never leak raw unmasked data.

## Shipped tools (`policy/manifest.json`)

62 tools total: 49 read-tier tools for inspection, and 13 write-tier tools for
reversible administration. All 13 write-tier tools require interactive human
elicitation from a distinct approver.

Local read tools run as virtual accounts on `McpBroker.ReadLocal`; AD/domain read
tools run as the gMSA on `McpBroker.ReadDirectory` so queries carry real Kerberos auth.
Write tools run on `McpBroker.Write` or `McpBroker.DirectoryWrite`.

### Read-Tier Tools (49)

| Category | Tools |
|---|---|
| JEA / broker diagnostics | `list-jea-endpoints`, `summarize-transcript-logs` |
| Server Manager | `list-windows-features` |
| Active Directory Domain Services | `query-ad-user`, `list-ad-computers`, `list-ad-groups`, `list-ad-organizational-units`, `list-read-only-domain-controllers`, `get-domain-password-policy`, `list-fine-grained-password-policies` |
| Group Policy | `list-group-policies` |
| AD Certificate Services | `list-certificate-authorities` |
| AD Federation Services | `list-adfs-relying-parties` |
| AD Lightweight Directory Services | `list-adlds-instances` |
| AD Rights Management Services | `list-rms-superusers` |
| DHCP / DNS Server | `list-dhcp-scopes`, `list-dns-zones` |
| File and Storage Services | `list-smb-shares`, `list-disks`, `list-storage-pools`, `list-directory-contents` |
| IIS (Web / FTP) | `list-iis-sites`, `list-ftp-sites` |
| Hyper-V | `list-hyperv-vms` |
| Print and Document Services | `list-printers` |
| Remote Desktop Services | `list-rds-collections` |
| WSUS / WDS | `list-wsus-updates`, `list-wds-boot-images` |
| Failover Clustering / NLB | `list-cluster-nodes`, `list-nlb-clusters` |
| BitLocker / AppLocker | `list-bitlocker-volumes`, `get-applocker-policy` |
| Windows Firewall / Networking | `list-firewall-rules`, `list-network-adapters` |
| Host Guardian Service / Network Controller | `get-hgs-status`, `get-network-controller-config` |
| NPAS (RRAS/VPN/DA) | `get-remote-access-status` |
| Storage Migration Service / System Insights | `list-storage-migration-jobs`, `list-system-insights-capabilities` |
| Local security policy | `get-local-security-policy`, `get-audit-policy`, `list-user-rights-assignments`, `get-execution-policy` |
| Local accounts / groups | `list-windows-services`, `list-local-users`, `list-local-groups`, `list-local-group-members`, `list-scheduled-tasks` |
| PS Remoting | `get-psremoting-status` |

### Write-Tier Tools (13 — Human Elicitation Required)

All write-tier tools are strictly bounded and reversible toggles. Every call requires
interactive human elicitation from a distinct approver identity on the approval pipe:

| Tool ID | Action & Target | Safety Boundary & Constraints |
|---|---|---|
| `set-scheduled-task-state` | Enable or disable a scheduled task | Reversible; task must exist; task path regex |
| `set-windows-service-state` | Start or stop a Windows service | Reversible; fixed critical service denylist (AD DS, RPC, WinRM, broker) |
| `set-firewall-rule-enabled` | Enable or disable a firewall rule | Reversible; rule must exist; rule name pattern |
| `set-local-user-enabled` | Enable or disable a local user account | Reversible; RID -500 built-in Administrator denied |
| `set-hyperv-vm-state` | Start or stop a Hyper-V VM | Reversible; VM must exist; VM name pattern |
| `set-iis-site-state` | Start or stop an IIS website | Reversible; site must exist; site name pattern |
| `set-cluster-node-state` | Pause or resume a failover cluster node | Reversible; node must exist; node name pattern |
| `set-wsus-update-approval` | Approve or decline a WSUS update | Reversible; valid GUID format; approval group required |
| `set-ad-user-enabled` | Enable or disable an Active Directory user | Reversible; RID -500 and -502 accounts denied |
| `set-ad-computer-enabled` | Enable or disable an AD computer account | Reversible; domain controllers denied |
| `set-ad-group-membership` | Add or remove an AD group member | Reversible; privileged groups (Domain/Enterprise Admins) denied; RID -500/-502 denied |
| `set-gpo-status` | Set GPO status (enabled/disabled components) | Reversible; Default Domain / Domain Controller policies denied |
| `set-dhcp-scope-state` | Activate or deactivate a DHCP scope | Reversible; valid IPv4 address format required |

`list-adlds-instances` has no dedicated AD LDS enumeration cmdlet to wrap — it discovers
instances via their `ADAM_<InstanceName>` service registration, the standard way to find
installed AD LDS instances without binding to a specific LDAP port. `get-local-security-policy`,
`get-audit-policy`, and `list-user-rights-assignments` have no native cmdlet either and wrap
`secedit.exe`/`auditpol.exe` — these are the only tools that invoke an external executable,
and `secedit.exe`/`auditpol.exe` are allowlisted per-tool via `jeaMapping.externalCommands`,
not granted broker-wide.

**Still genuinely not covered** — no supported PowerShell cmdlet exists, or the role is
removed from current Windows Server: Device Health Attestation (web.config only), MultiPoint
Services (removed since 2016), Fax Server (FXSCOMEX COM API only), Volume Activation Services
(`slmgr.vbs`/VAMT only), Windows Server Essentials Experience (removed).

### Security fixes applied during review

- **`list-directory-contents` allowlist of roots.** The traversal regex (blocks any
  `..` substring, requires a drive-absolute path) only rejects bad *syntax* — it doesn't
  stop a syntactically valid path from pointing at sensitive locations. Replaced the
  incomplete denylist with an explicit allowlist of permitted root prefixes (e.g.
  `C:\Shares`, `C:\Data`), configurable via `BROKER_ALLOWED_ROOTS`. Any path not resolving
  under an allowed root is rejected via canonicalized case-insensitive prefix matching,
  alongside existing traversal (`..`), reparse-point (symlink/junction/mount), and
  500-entry bounds.
- **Unbounded AD-DS/GPO enumeration.** `Get-ADComputer -Filter *`, `Get-ADGroup -Filter *`,
  `Get-ADOrganizationalUnit -Filter *`, and `Get-GPO -All` had no result limit. In a large
  domain (tens of thousands of objects) this risks exceeding the broker's 1MiB frame cap
  and needlessly loading the domain controller. Bounded via `-ResultSetSize 1000` (native
  AD cmdlet parameter, stops the query server-side) or `Select-Object -First 500`/`-First 500`
  for `Get-GPO`/`Get-VM`/`Get-SmbShare`/`Get-Printer`, which have no native equivalent.
  Smaller-scope enumerations (services, disks, scheduled tasks, local groups, NICs — bounded
  by hardware/OS, not directory scale) were left as-is; adding a bound there would be
  cosmetic, not a real fix.

**None of the 46 tools added since the original 3 have been run against a real installed
role** (no AD/DNS/DHCP/Hyper-V/IIS/etc. host in this environment) — unlike the original 3
tools, which got real PSObject-serialization and signature scrutiny. `generate-jea`
validates the manifest/JEA-config shape only, not that each wrapped cmdlet actually
returns what the wrapper assumes.

## AI & Automated End-to-End Configuration

The repository ships an AI-first auto-configuration engine (`deploy/auto-configure.ps1`) and CLI diagnostics (`Broker.Host self-check`) enabling an AI agent or orchestration tool to configure and validate the broker with zero manual guesswork.

All script commands emit **pure, structured JSON** to standard output (progress logs to stderr) for direct programmatic consumption.

```powershell
# 1. Host Discovery (inspects OS, domain, current user SID, certs, installed features)
powershell -ExecutionPolicy Bypass -File deploy\auto-configure.ps1 -Discover

# 2. Plan Generation (creates tailor-made broker-profile.json for Dev or Production)
powershell -ExecutionPolicy Bypass -File deploy\auto-configure.ps1 -Plan -DevMode

# 3. Apply Configuration (signs .psm1 modules, updates manifest.json & appsettings.json, regenerates JEA)
powershell -ExecutionPolicy Bypass -File deploy\auto-configure.ps1 -Apply -ProfilePath deploy\broker-profile.json

# 4. Health Validation (verifies zero placeholders, signature validity, and self-checks)
powershell -ExecutionPolicy Bypass -File deploy\auto-configure.ps1 -Validate

# ONE-SHOT FULL AUTO-CONFIGURATION:
powershell -ExecutionPolicy Bypass -File deploy\auto-configure.ps1 -Full -DevMode

# Direct Binary Diagnostics (exits 0 if clean, 1 with JSON diagnostics if placeholders remain):
dotnet run --no-restore --project src/Broker.Host -- self-check
```

See [`docs/ai-autoconfiguration.md`](file:///C:/Users/mingk/Desktop/windows%20server%20MCP/docs/ai-autoconfiguration.md) for complete JSON schemas, parameter contracts, and production deployment flows.

## Build

```powershell
dotnet build mcp-broker.sln -c Release
dotnet publish src/Broker.Host/Broker.Host.csproj -c Release -o publish
```

## Deploy (operator, elevated — review each script first)

```powershell
# 1. Place signed wrapper modules under C:\McpBroker\jea
# 2. Generate JEA configs from the manifest (programmatic: JeaConfigGenerator.GenerateAll)
# 3. Register endpoints
.\deploy\register-jea.ps1 -GeneratedDir .\jea\generated
# 4. Lock execution to signed binaries (start in Audit)
.\deploy\setup-wdac.ps1 -ServerPath 'C:\McpBroker\jea' -Mode Audit
# 5. Install the service under the gMSA
.\deploy\install-service.ps1 -PublishDir .\publish -GmsaAccount 'CONTOSO\McpBrokerSvc$' -AllowedClientSid 'S-1-5-21-...'
```

## Config

`src/Broker.Host/appsettings.json` — pipe name, allowed client SIDs (allowlist, no
`Everyone`), manifest path, transcript dir, rate limits.

## Hardening status

Correctness fixes applied and covered by `test/Broker.Tests` (28 tests):
- Elicitation no longer deadlocks — the pipe reader demuxes frames and dispatches
  concurrently; approvals have a configurable TTL (`Elicitation:TtlSeconds`).
- Signature verification uses WinVerifyTrust (file hash + chain) and cross-checks the
  signer thumbprint; works for PE and `.psm1`.
- JEA `.pssc` `RoleDefinitions` keys on a real `accessGroup`; `.psrc` imports the wrapper
  module via `ModulesToImport`.
- JEA invocation runs cleanly under `NoLanguage` (no in-session script); output `PSObject`s
  are flattened so JSON is populated, not `{}`.
- Caller taint window (`Taint:WindowSeconds`): a caller that received untrusted-source
  output cannot drive a write/destructive tool until the window expires.
- Separation of duties (`Elicitation:RequireDistinctApprover` + `ApproverSids`): a caller
  cannot self-approve; the approver must be distinct and allowlisted.
- Revocation cancels in-flight elicitations for the revoked tool.

## Approval delivery (distinct-approver mode)

When `Elicitation:RequireDistinctApprover` is `true`, destructive/write calls are routed
through `ElicitationRouter` to a second, separately ACL'd named pipe
(`Elicitation:ApprovalPipeName`, default `McpBroker.Approvals`), restricted to
`Elicitation:ApproverSids`. The approver's identity is captured from that pipe connection
(`RunAsClient`), never taken from the request body — so a caller cannot forge itself as the
approver. `ConsentEngine` then rejects if the approver equals the caller or isn't allowlisted.
Covered by `ElicitationRouterTests` and the transport integration tests.

## Operator CLI & Runtime Tools

### JEA Configuration Generator
```powershell
dotnet run --project src/Broker.Host -- generate-jea policy/manifest.json jea/generated
```
Renders `.psrc`/`.pssc` from the manifest and exits (no pipe listener started). Enforces non-broad access groups (rejects `BUILTIN\Users`, `Everyone`, `Authenticated Users`), validates module names, and removes stale JEA configuration artifacts.

### MCP Stdio Adapter (`Broker.McpAdapter`)
Translates standard Model Context Protocol (MCP) JSON-RPC 2.0 stdio requests from AI host clients (Claude Desktop, Cursor, Cline) to the broker's ACL-restricted named pipe:
```powershell
dotnet run --project src/Broker.McpAdapter -- --pipe McpBroker --manifest policy/manifest.json
```

### Standalone Approver CLI (`Broker.ApproverCli`)
Connects to the separate approval pipe (`\\.\pipe\McpBroker.Approvals`) under an authorized human operator identity. Displays pending tool requests, parameter values, caller SID, and expiry, allowing interactive human authorization (`[y/N]`) for write-tier operations:
```powershell
dotnet run --project src/Broker.ApproverCli -- --pipe McpBroker.Approvals
```

## Testing

`test/Broker.Tests` (67 tests), run on real Windows, no mocking of the OS layer where it
matters:

- **PSObject serialization tests** against the real `System.Management.Automation` types
  (not fakes) — covers the original "JEA output comes back as `{}`" bug (critique item 5):
  `PSCustomObject` flattening, nested objects, arrays, `Hashtable`, wrapped primitives.
  Building these correctly required discovering the SDK's actual construction quirks
  (`new PSObject(x)` does not do what its signature suggests; `PSObject.AsPSObject` and
  direct `.Properties.Add` — not the `.PSObject.Properties` double-wrap — are the real APIs).
- **JeaConfigGenerator tests** — endpoint consolidation, native `ValidateSet`/`ValidatePattern`/
  `ValidateRange` emission, gMSA vs. virtual-account `.pssc` output, and the validation guards
  (missing `moduleName`/`accessGroup`, mismatched `accessGroup` across tools on one endpoint)
  that make a misconfigured manifest fail loudly at generation time.

- **Policy/framing unit tests** — allowlist, rate limiting, consent, taint, framing bounds.
- **BrokerPipeline gate-order tests** — the real 8-gate pipeline (manifest lookup, signature,
  taint, params, untrusted-source, rate limit, elicitation, JEA invoke) driven end to end with
  real `ManifestStore`/Policy components and a fake `ISignatureVerifier`; every scenario is
  rejected before gate 8, so no live JEA session is needed. This was previously the single
  largest coverage gap — the component tying every other fix together had zero tests.
- **Transport integration tests** — `NamedPipeServer.ServeAsync` driven over an in-memory
  duplex stream (`ChannelStream`), no OS pipe needed. `ElicitationApprovedCompletesCallWithoutDeadlock`
  is a regression guard: it fails fast via `WaitAsync` instead of hanging if the
  reader/dispatch coupling that caused the original elicitation deadlock is ever reintroduced.
- **SignatureVerifier tests against a real signed file** (`C:\Windows\System32\notepad.exe`) —
  not a mock. This caught a real bug during development (below).
- **ManifestStore revocation tests** against a real `FileSystemWatcher`, and `CorrelationLog`
  JSONL round-trip tests.

```powershell
dotnet test mcp-broker.sln
```

### Real bug found and fixed during testing: catalog-signature verification

Testing `SignatureVerifier` against `notepad.exe` (real, not mocked) surfaced a genuine
correctness bug: `WinVerifyTrust` called with plain `WTD_CHOICE_FILE` only checks an
*embedded* Authenticode signature. Most Windows system binaries — and potentially some
vendor-deployed MCP servers — are **catalog-signed** instead, where the signature lives in a
separate `.cat` file, not the binary itself. The original implementation returned
`TRUST_E_NOSIGNATURE` for these and would have incorrectly rejected a validly signed, properly
registered server.

Fixed by adding an explicit catalog lookup fallback (`CryptCATAdminAcquireContext2` /
`CryptCATAdminCalcHashFromFileHandle2` / `CryptCATAdminEnumCatalogFromHash`) that triggers
specifically when the embedded check fails with `TRUST_E_NOSIGNATURE`, then re-verifies via
`WTD_CHOICE_CATALOG`. This mirrors what `Get-AuthenticodeSignature` does internally. Verified
against the real OS signature store: correct thumbprint accepted, wrong thumbprint rejected,
missing file rejected, unsigned file rejected — all against actual Windows APIs, not fakes.

## Residual risk / remaining work

- **Cross-turn taint is an approximation.** The broker cannot see what the LLM does between
  calls; the taint window is a conservative server-side bound, not true data-flow tracking.
- **Behavioral safety.** Signature verification proves provenance, not that a signed server
  won't change behavior later (time bomb / malicious update). Mitigated by code review of
  registered servers, not by this layer.
- **AMSI fails open.** If no AMSI provider is registered on the host, `AmsiScanner` logs a
  warning and allows — AMSI is a second opinion against known-bad byte patterns, not the
  primary gate (the allowlist/JEA layers are).
- **JEA/WSMan and gMSA still unverified end-to-end.** Signature verification and pipe/manifest
  logic are now proven against real Windows APIs. `JeaEndpointClient`'s WSMan loopback to an
  actual registered JEA endpoint, and the approval pipe's real SID-based ACL enforcement,
  still need a domain-joined Windows Server with a gMSA and registered endpoints — that
  infrastructure doesn't exist in this environment.
"# Windows-Server-MCP" 

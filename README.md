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
1 manifest lookup  ->  2 signature re-check  ->  3 risk tier  ->  4 parameter validate
   ->  5 untrusted-source gate  ->  6 rate limit  ->  7 elicitation  ->  8 JEA invoke
```

Any gate that does not explicitly allow terminates the call. The untrusted-source gate is
a hard stop with no elicitation override: data that may carry injected content (AD
attributes, file contents, network responses) can never reach a write/destructive tool.

## Security principles

- **Read-only first** — the shipped manifest contains only query tools.
- **Destructive = human confirm** or generate-script-don't-execute.
- **No credentials in LLM context** — execution uses the gMSA's Kerberos identity.
- **Prompt-injection defense** — untrusted external data never auto-triggers a write tool.
- **Masking** — sensitive output fields (SIDs, DNs) are redacted before return.

## Shipped tools (`policy/manifest.json`)

49 tools, all read tier, no elicitation. Local tools run as a virtual account on
`McpBroker.ReadLocal`; AD/domain tools run as the gMSA on `McpBroker.ReadDirectory` so
queries carry real Kerberos auth. Nothing writes state — every tool is a `Get-*` cmdlet.

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

- **`list-directory-contents` had no scope restriction.** The traversal regex (blocks any
  `..` substring, requires a drive-absolute path) only rejects bad *syntax* — it doesn't
  stop a syntactically valid path from pointing at `C:\Windows\System32\config` (SAM/SYSTEM
  hive backups), `C:\ProgramData\Microsoft\Crypto` (DPAPI/machine keys), or user profile
  folders. Added an explicit denylist of sensitive path prefixes inside the wrapper itself,
  as defense in depth beyond what a regex can express semantically.
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

## Operator CLI

```powershell
dotnet run --project src/Broker.Host -- generate-jea policy/manifest.json jea/generated
```

Renders `.psrc`/`.pssc` from the manifest and exits (no pipe listener started). Refuses with
a clear error if a tool is missing `jeaMapping.accessGroup` or `moduleName`, or if two tools
on one endpoint disagree on `accessGroup`. This is the step between editing the manifest and
running `deploy/register-jea.ps1`.

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

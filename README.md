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
0 caller identity -> 1 manifest lookup -> 2 signature re-check -> 3 risk tier / caller taint
   -> 4 parameter validate -> 4b AMSI -> 5 untrusted-source gate -> 6 rate limit
   -> 7 elicitation (then taint, revocation and signature are checked again)
   -> 8 JEA invoke (bounded) -> 9 output masking
```

Any gate that does not explicitly allow terminates the call, and so does a gate that throws. The
untrusted-source gate is a hard stop with no elicitation override: a tool whose output may carry
injected content (AD attributes, file contents, network responses) can never be a write or
destructive tool. A denied request never reaches PowerShell; the tests assert that the executor was
not called.

## Security principles

- **Read-only first** — all but 13 reversible write tools are query tools.
- **Destructive = human confirm** or generate-script-don't-execute. No destructive tool ships.
- **No credentials in LLM context** — execution uses the gMSA's Kerberos identity.
- **Prompt-injection defense** — untrusted external data never auto-triggers a write tool. This is
  caller-level and time-boxed, not data-flow tracking; see Residual risk.
- **Masking** — configured output fields (SIDs, DNs) are redacted before return, and a payload that
  cannot be masked is withheld rather than returned raw. Which fields each read tool returns, and what
  is masked, is in `docs/read-tier-output-inventory.md`.

## Shipped tools (`policy/manifest.json`)

62 tools: 49 read tier (no elicitation) and 13 write tier (human elicitation from a
distinct approver required). Local read tools run as a virtual account on
`McpBroker.ReadLocal`; AD/domain read tools run as the gMSA on `McpBroker.ReadDirectory`
so queries carry real Kerberos auth. Local write tools run on `McpBroker.Write`;
AD/domain write tools run as the gMSA on `McpBroker.WriteDirectory`. No tool is
destructive tier — every write is reversible (enable/disable, start/stop,
pause/resume, approve/decline), never a delete or create.

### Read tier

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

### Write tier (elicitation required)

Every write tool is reversible and carries an in-wrapper denylist/allowlist beyond the
broker's own parameter validation where a wrong value could be catastrophic (critical
services, domain controllers, privileged AD groups, the broker's own gMSA).

| Category | Tools |
|---|---|
| Scheduled Tasks | `set-scheduled-task-state` |
| Windows Services | `set-windows-service-state` (denies AD DS, Netlogon, KDC, time sync, RPC, DCOM, WinRM, the broker's own service) |
| Windows Firewall | `set-firewall-rule-enabled` |
| Local accounts | `set-local-user-enabled` |
| Hyper-V | `set-hyperv-vm-state` |
| IIS (Web/FTP) | `set-iis-site-state` |
| Failover Clustering | `set-cluster-node-state` (pause/resume only, never evicts a node) |
| WSUS | `set-wsus-update-approval` |
| Active Directory Domain Services | `set-ad-user-enabled` (denies krbtgt, built-in Administrator, the broker's gMSA), `set-ad-computer-enabled` (denies domain controllers), `set-ad-group-membership` (denies Domain Admins/Enterprise Admins/Administrators) |
| Group Policy | `set-gpo-status` |
| DHCP Server | `set-dhcp-scope-state` (activate/deactivate only, never deletes a scope) |

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

On a non-Windows machine the projects target `net8.0-windows`, so building needs
`-p:EnableWindowsTargeting=true` (compiles, and runs the cross-platform tests, but cannot run
anything that needs Windows):

```bash
dotnet build mcp-broker.sln -c Release -p:EnableWindowsTargeting=true
```

## Deploy (operator, elevated — review each script first)

```powershell
# 1. Place signed wrapper modules under C:\McpBroker\jea
# 2. Generate JEA configs from the manifest (see "Operator CLI")
# 3. Register endpoints
.\deploy\register-jea.ps1 -GeneratedDir .\jea\generated
# 4. Build the WDAC policy in Audit mode, deploy it by hand, let it run, then promote it
.\deploy\setup-wdac.ps1 -ServerPath 'C:\McpBroker\jea' -Mode Audit
#    ... at least a week later, after reviewing the Code Integrity log:
.\deploy\setup-wdac.ps1 -ServerPath 'C:\McpBroker\jea' -Mode Enforced -ConfirmEnforcement "ENFORCE $env:COMPUTERNAME"
# 5. Install the service under the gMSA
.\deploy\install-service.ps1 -PublishDir .\publish -GmsaAccount 'CONTOSO\McpBrokerSvc$' -AllowedClientSid 'S-1-5-21-...'
```

`setup-wdac.ps1` only builds policy files; it never deploys one. Read `docs/security-hardening.md`
(WDAC) before enforcing.

## Config

`src/Broker.Host/appsettings.json`. Every numeric key is validated at startup: an unparsable value
stops the service rather than silently falling back to a default.

| Key | Default | Meaning |
|---|---|---|
| `Pipe:AllowedSids` | one placeholder | Client SIDs. Broad principals (Everyone, Authenticated Users, Domain Users, ...) are refused at startup. |
| `Pipe:MaxInstances` | 8 | Pipe slots. |
| `Pipe:MaxConnectionsPerCaller` | half of `MaxInstances` | Connections one caller may hold at once. |
| `Pipe:MaxInFlightPerConnection` | 16 | Concurrent requests per connection. |
| `Pipe:MaxMalformedRequests` | 5 | Malformed messages tolerated before the connection is closed. |
| `Pipe:FrameTimeoutSeconds` / `Pipe:WriteTimeoutSeconds` | 5 / 10 | Partial-frame and stalled-write limits. |
| `Manifest:*` | integrity on | Path and integrity-sidecar settings. Keep `RequireIntegrity` true. |
| `Elicitation:*` | distinct approver | TTL, approval pipe, `ApproverSids`. |
| `Taint:WindowSeconds` | 300 | Caller taint window. |
| `Amsi:Mode` | `BestEffort` | `Strict` denies a call when AMSI cannot answer. |
| `RateLimit:CallsPerMinute` / `DestructivePerHour` / `GlobalCallsPerMinute` | 60 / 10 / 600 | Per caller, and across all callers (0 disables only the global limit). |
| `Jea:OpenTimeoutMs` / `Jea:OperationTimeoutMs` | 30000 / 60000 | WSMan timeouts. |
| `Jea:Limits:*` | see file | Concurrency (total / endpoint / tool), queue length and wait, execution timeout, max response bytes. |

## Behaviour worth knowing

- **Write and destructive tools always require approval.** `requiresElicitation: false` cannot turn
  it off, and an unrecognized `riskTier` is treated as the most restrictive tier (and the tool is
  not registered at all).
- **Hot reload can only revoke.** Editing the manifest while the service runs can remove a tool or set
  `"revoked": true`. Additions and any other change (tier, parameters, allowlists) take effect only
  after a restart. A failed integrity check on reload revokes every tool.
- **Editing the manifest** requires regenerating its SHA-256 sidecar. `.gitattributes` pins both files
  to LF so the hash is the same on every checkout:
  `(Get-FileHash policy\manifest.json -Algorithm SHA256).Hash | Set-Content -NoNewline policy\manifest.json.sha256`
- **A timeout is "outcome unknown".** If a JEA call exceeds `ExecutionTimeoutSeconds` the caller is told
  `jea-timeout` and cancellation is requested, but the broker does not claim the work stopped; the
  concurrency slot stays occupied until the underlying call actually returns.
- **JSON parameters** may be strings, numbers or booleans. `true`/`false` arrive as `"true"`/`"false"`,
  numbers keep their exact text (so an integer parameter rejects `1.5`), and objects, arrays, `null` and
  duplicate names are rejected as malformed.
- The approver is shown the validated parameters, not just a hash.
- **A tool id** must be a plain identifier (`^[a-z0-9]+(-[a-z0-9]+)*$`, at most 100 characters).
  An unknown parameter name is echoed in a reject reason only if it is a plain identifier.
- **A `resourceAllowlist` entry applies to a required parameter.** A scope on an optional parameter, or on a
  parameter the tool does not define, denies the call rather than being skipped.
- **`generate-jea` is strict about its input and its output directory.** Cmdlet, module, endpoint, gMSA,
  role-capability and parameter names must be plain identifiers (they are written into PowerShell data
  files that decide what JEA exposes); it refuses to run if the output directory already holds
  `.psrc`/`.pssc` files that are not part of this manifest (`register-jea.ps1` would register them too),
  and it never deletes anything.
- **A bad setting stops startup.** The service refuses to start (exit code 1, naming the key) rather than
  falling back to a default; a failed startup self-check also exits non-zero.

## Hardening status

What the code enforces, and how that is checked (test classes in `test/Broker.Tests`):

- Elicitation does not deadlock: the pipe reader demuxes frames and dispatches concurrently
  (`TransportIntegrationTests`).
- Approver identity comes only from OS impersonation of the connection, never from a message field
  (`TransportIntegrationTests.ForgedDecidedBySidInReplyIsIgnoredAndRealCallerSidIsUsed`,
  `ApprovalPipeServeTests`; the real-pipe versions are `WindowsPipeIdentityTests`, Windows only).
- An approval is bound to one operation: correlation id, tool, and a hash of tool + caller + parameters;
  `ConsentEngine.Verify` has no optional parameters (`ConsentEngineToolBindingTests`,
  `ElicitationRouterBindingTests`, `PipelineSecurityTests`).
- Validation and conversion share one definition of each type (`ParameterTypes`), so a value cannot pass
  one parser and fail another (`TypedParameterTests`).
- Every gate fails closed, including a gate that throws; a denied request never reaches PowerShell
  (`PipelineSecurityTests`, which asserts the executor was not called).
- Taint is set before an untrusted-source tool runs, and re-checked after a human approves
  (`PipelineSecurityTests`, `TaintTrackerBehaviourTests`).
- Concurrency, queueing, timeouts and response size are bounded (`BoundedJeaExecutorTests`); so are
  per-connection requests, stalled writes and per-caller connections (`TransportSecurityTests`,
  `TransportResourceLimitTests`).
- Signature verification uses WinVerifyTrust (file hash + chain) and cross-checks the signer thumbprint;
  works for PE and `.psm1` (`SignatureVerifierRealFileTests`, Windows only).
- JEA `.pssc` `RoleDefinitions` keys on a real `accessGroup`; `.psrc` imports the wrapper module via
  `ModulesToImport` (`JeaConfigGeneratorTests`).
- Revocation is the only hot-reload action, cancels in-flight approvals for the revoked tool, and works
  for atomic-rename publishing (`ManifestStoreRevocationTests`, `ManifestStoreHardeningTests`).
- Output of read tools is explicitly projected and classified (`docs/read-tier-output-inventory.md`,
  `OutputSchemaInventoryTests`, `WrapperHygieneTests`).

## Approval delivery (distinct-approver mode)

When `Elicitation:RequireDistinctApprover` is `true`, write and destructive calls are routed
through `ElicitationRouter` to a second, separately ACL'd named pipe
(`Elicitation:ApprovalPipeName`, default `McpBroker.Approvals`), restricted to
`Elicitation:ApproverSids`. The approver's identity is captured from that pipe connection
(`RunAsClient`), never taken from the request body, so a caller cannot forge itself as the
approver. Replies from a SID outside `ApproverSids` are ignored (the pipe ACL also admits the
service's own identity), and `ConsentEngine` then rejects if the approver equals the caller.

## Operator CLI

```powershell
dotnet run --project src/Broker.Host -- generate-jea policy/manifest.json jea/generated
```

Renders `.psrc`/`.pssc` from the manifest and exits (no pipe listener started). Refuses with
a clear error if a tool is missing `jeaMapping.accessGroup` or `moduleName`, or if two tools
on one endpoint disagree on `accessGroup`. This is the step between editing the manifest and
running `deploy/register-jea.ps1`. The files under `jea/generated` are build output (the directory
is git-ignored; the few that are tracked are stale snapshots). Regenerate, do not deploy them as-is.

## Testing

```bash
dotnet test mcp-broker.sln                                           # Windows: everything runs
dotnet test mcp-broker.sln -p:EnableWindowsTargeting=true            # elsewhere: Windows-only tests are skipped
```

The suite has three kinds of test. The counts below are from one run of this revision on Linux
(`dotnet test`, SDK 8.0.132) and will change as tests are added; the CI workflow is the record, not
this paragraph.

| Kind | What it can establish | Needs |
|---|---|---|
| Cross-platform unit and in-process tests | Policy, pipeline gate order and fail-closed behaviour, parsing, limits, manifest handling, PowerShell script syntax, wrapper source checks, the WDAC readiness logic (really executed through the in-process PowerShell engine) | Nothing |
| `[WindowsOnlyFact]` tests | WinVerifyTrust against a real signed file, real named-pipe ACL and impersonation identity, real AMSI | A Windows host. Reported as **skipped**, never passed, elsewhere |
| Not in this repository | AD/gMSA/Kerberos, a registered JEA endpoint reached over WSMan, any real Windows Server role, WDAC enforcement, a second principal being refused by a pipe ACL | A domain-joined test environment (see `docs/security-hardening.md`) |

Last local run: 572 tests, 564 passed, 0 failed, 8 skipped (all Windows-only). The Windows-only tests
have not been executed by the author of this revision; the CI Windows job (`.github/workflows/ci.yml`)
is where they run, and it fails if any test is skipped.

The wrapper and inventory checks (`OutputSchemaInventoryTests`, `WrapperHygieneTests`) read the PowerShell
source as text. They show what the wrappers are written to return, not what a real role returns.

### History of the test suite

An earlier revision of this README described a suite of 28, then 67, and `docs/security-audit.md`
reported 82 passing tests, with details of experiments run on a Windows machine. That suite
(`test/Broker.Tests`) was deleted from the tree in commit `e14e58c` and removed from the solution, so
for a time those statements described code that was not in the repository. It was restored from
`0ffc554` (82 tests, of which 3 failed off Windows because they reached the real WSMan client) and
extended. Figures from the old experiments are not repeated here because they cannot be reproduced from
this repository.

### Catalog-signed files

`WinVerifyTrust` with plain `WTD_CHOICE_FILE` checks only an *embedded* signature, but most Windows
system binaries are catalog-signed, so the verifier falls back to an explicit catalog lookup
(`CryptCATAdmin*`, then `WTD_CHOICE_CATALOG`) when the embedded check returns `TRUST_E_NOSIGNATURE`.
This was recorded by an earlier author as found while testing against `notepad.exe`; the Windows-only
`SignatureVerifierRealFileTests` cover it and have not been re-run in this revision.

## Residual risk / remaining work

See `docs/security-audit.md` for the full list. In short:

- **Taint is per caller, not per value.** The broker cannot see what the LLM does with a value between
  calls; the window is a conservative bound. Many read tools return free text that others can author (VM
  names, service names, task names) and are deliberately *not* tagged, because tagging would block the
  list-then-act workflow; the human approver is the control there (`docs/read-tier-output-inventory.md`).
- **Behavioural safety.** Signature verification proves provenance, not that a signed module won't change
  behaviour later. Mitigated by code review of registered modules, not by this layer.
- **AMSI is supplementary.** In the default `BestEffort` mode an unavailable AMSI provider is logged and the
  call continues, so the layer does nothing on such a host. `Strict` denies instead.
- **Not verified end to end.** The WSMan loopback into a real JEA endpoint, gMSA/Kerberos, a real pipe
  ACL refusing a different principal, WDAC enforcement, and every wrapper's output against a real role need a
  domain-joined Windows Server test environment that this repository does not have.

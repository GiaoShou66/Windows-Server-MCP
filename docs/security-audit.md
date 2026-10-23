# Windows-Server-MCP Security Audit

This document records what was found, what was changed, and, for each item, how strongly the result
is established. It distinguishes **confirmed vulnerabilities and defects** from **hardening
improvements**, and it states what was *not* tested.

## 1. Scope, method and evidence

Reviewed: the broker request path (`Broker.Transport`, `Broker.Host.BrokerPipeline`), manifest loading
(`Broker.Registry`), policy gates (`Broker.Policy`), elicitation and approval, JEA invocation
(`Broker.JeaExecution`), the PowerShell wrappers and generated JEA configuration, the deployment
scripts, transcript correlation, and the test suite.

A supplied review was treated as a list of hypotheses to check against the source, not as fact. Section
4 lists where it was wrong or imprecise.

### Evidence levels

| Tag | Meaning |
|---|---|
| **R→G** | A test was run against the **old** code and **failed**, then passed after the fix. |
| **C→G** | The test could not compile against the old code (the API itself was the defect), then passed. |
| **M** | The fix was later broken on purpose (a *mutation*) and at least one test failed. Run by an ad-hoc script, not part of CI. |
| **S** | Static check of source text. Shows what the code is written to do, not what a real Windows role returns. |
| **W** | A `[WindowsOnlyFact]` test exists but has **not been executed** by the author (no Windows host). Reported as skipped elsewhere. |
| **X** | Not tested. |

### Commands run and results (Linux, .NET SDK 8.0.132)

```text
dotnet build mcp-broker.sln -c Release -p:EnableWindowsTargeting=true
  Build succeeded. 0 Warning(s), 0 Error(s)

dotnet test mcp-broker.sln -c Release -p:EnableWindowsTargeting=true
  Passed!  - Failed: 0, Passed: 564, Skipped: 8, Total: 572

python3 .github/scripts/check-skips.py <trx> --allow "Requires Windows"
  572 tests: 564 passed, 0 failed, 8 skipped, 0 other   (exit 0)
```

The 8 skipped tests are the `[WindowsOnlyFact]` tests (`SignatureVerifierRealFileTests` ×4,
`WindowsPipeIdentityTests` ×3, `AmsiScannerTests.RealAmsiOnWindowsAcceptsABenignParameterSet`).
They are skipped with the reason "Requires Windows … NOT executed here". `.github/workflows/ci.yml`
defines a Windows job that must run all of them with zero skips; **that workflow has not been run**.

Composition root, run for real (not a test): the host was started from a temporary directory with its
config pointed at the repository manifest. The dependency graph resolved; the manifest loaded **62 tools
with integrity enforced** from the committed sidecar; the startup self-check failed for all 62 tools (the
wrapper files are not at their `C:\McpBroker\jea` paths on this machine); the host logged
`Startup self-check failed; refusing to open pipe listener`, opened no pipe, and exited with code 1.
`generate-jea` produced 66 files (62 role capabilities, 4 session configurations).

Mutation checks: 30 deliberate breakages of the implementation (unbounded queue, off-by-one limits,
approver list not enforced, tool comparison removed, masking fail-open, taint re-check removed,
watcher not subscribed to `Renamed`, wrapper gaining `Select-Object *`, generator skipping identifier
validation, configuration falling back silently, and so on) were each caught by at least one test.

## 2. Corrections to earlier statements

- **The test suite was not "missing"; it had been deleted on purpose.** An earlier review of this
  repository reported documented tests as absent and, by implication, unsupported. The history shows
  `test/Broker.Tests` was added in `1110100`, extended through `0ffc554`, and deleted in `e14e58c`
  (the merge commit `e0e9ab8` records that as a decision). It has been restored from `0ffc554`.
  What *was* wrong: the README and this file kept describing it (28, 67 and 82 tests; experiments on a
  Windows host) while the tree contained no tests, and some restored tests passed vacuously off Windows.
- **The `TaskPath` analysis was wrong in its details.** The old pattern's `\\$` is an escaped backslash
  followed by the end anchor, not a literal `$`. The real defects are in A2 below.
- **`CaptureCallerSid` did not swallow exceptions.** They propagated and closed the connection (fail
  closed). The real gap was a *blank* SID flowing through as a caller identity (A10).

## 3. Findings

### 3.1 Confirmed vulnerabilities and defects (fixed)

| ID | Where | Defect | Fix | Tests | Evidence |
|---|---|---|---|---|---|
| A1 | `Policy.cs` `ParameterValidator.CheckOne`, `ArgvBuilder.Build` | A range value was parsed with a culture-sensitive `double.TryParse`; `NaN` passes every bound comparison, and `1e1`, `1.5`, `" 5"`, `"+5"` passed validation and then made `int.Parse` throw `FormatException`, which `DispatchAsync` did not catch. Nothing reached PowerShell, but validation and conversion disagreed and an exception escaped the dispatcher. | One definition of each type (`ParameterTypes`: invariant culture, ASCII, canonical) used by both; builder refusals are `InvalidOperationException` without the value. | `TypedParameterTests`, `PipelineSecurityTests.InvalidIntegerIsRejectedBeforeAnyExecution` | R→G (38 failures), M |
| A2 | `policy/manifest.json` `set-scheduled-task-state.TaskPath` | The pattern `^\\[\\A-Za-z0-9 _.-]*\\$` **rejected the root folder `\`** and **accepted** `\\`, `\.\`, `\..\` and the UNC path `\\server\share\`. | `^\\(?:(?!\.+\\)[A-Za-z0-9 _.-]+\\)*\z`, identical in manifest, wrapper and generated `.psrc` (asserted). | `TaskPathValidationTests` | R→G (8 failures with the old pattern) |
| A3 | `Registry.cs` `ToolManifest` | An unrecognized `riskTier` mapped to **Read**, and `requiresElicitation: false` **switched approval off for a write tool**. A typo or edited manifest ran a mutating tool unattended and skipped the taint gate. | Unknown tier → most restrictive tier and the tool is not registered; write/destructive always require approval. | `ManifestTierHardeningTests`, `ManifestStoreHardeningTests`, `PipelineSecurityTests` | R→G |
| A4 | `Registry.cs` `ManifestStore.Reload` | The class documented that hot reload only revokes, but the code swapped in the whole new file, so a live edit could add a tool, lower a tier or loosen an allowlist. | Reload is narrowing-only; other changes are logged and wait for a restart. | `ManifestStoreHardeningTests` | R→G (6 failures), M |
| A5 | `Registry.cs` watcher | The watcher ignored `Renamed`, so a revocation published by writing a temp file and renaming it over the manifest was **never applied**. | Subscribe to `Renamed`. | `ManifestStoreHardeningTests.ARevocationDeliveredByAtomicRenameIsStillApplied` | R→G (timeout), M. Windows watcher semantics: W (runs in the Windows CI job) |
| A6 | `BrokerPipeline` | Taint was set only **after** an untrusted-source tool succeeded, never when it failed, and was not re-checked after a human approved. A write approved at T could run after the caller had since read untrusted data. | Taint before execution (also on failure); taint, revocation and signature re-checked immediately before execution. | `PipelineSecurityTests` | R→G, M |
| A7 | `BrokerPipeline.MaskFields` | A payload that failed to parse was returned **unmasked**; parsing and re-serializing every number as `double` corrupted integers above 2^53. | Mask the JSON tree (exact numbers); a payload that cannot be masked is withheld (`output-masking-failed`). | `PipelineSecurityTests`, `OutputSchemaInventoryTests` | R→G, M |
| A8 | `BrokerPipeline`, `JeaEndpointClient` | A throwing signature verifier, a validator regex timeout, a throwing executor, a failing elicitation channel, or a failing correlation log (**after the call had already executed**) escaped `DispatchAsync` as an exception. | Every gate is guarded and a throw is a rejection; an audit-sink failure after execution is logged and does not hide the result. | `PipelineSecurityTests` | R→G |
| A9 | `policy/manifest.json.sha256` | The committed hash was computed over a CRLF working copy while git stores LF, so any checkout without CRLF conversion failed the integrity check and the broker loaded **zero tools**. | `.gitattributes` pins the policy files to LF; sidecar regenerated; a test compares the committed hash with the committed bytes. | `ShippedManifestInvariantTests`, `ShippedManifestFixture` | Found by the failing fixture |
| A10 | `Transport.cs` | A blank impersonated SID was served as a caller identity; unknown message types were treated as tool calls; non-boolean `approved` threw; `parameters` that was not an object was silently dropped; nested/`null`/duplicate parameter values were accepted; JSON `true` became `"True"` (rejected by the lower-case enum). | Refuse blank identity; strict message parser; only the literal `true` approves; scalars only, duplicates rejected; booleans canonicalized. | `TransportSecurityTests` | C→G, M |
| A11 | `ApprovalPipeServer` | The pipe ACL always admits the service's own identity, and nothing checked an approver against `ApproverSids` before consuming the pending request; approvers were shown only an opaque hash, so they could not review what they approved. | Replies from SIDs outside the list are ignored; the validated parameters are included in the approval request. | `ApprovalPipeServeTests` | C→G, M |
| A12 | `Policy.cs` `ConsentEngine.Verify` | `expectedToolId`/`replyToolId` were optional (default `null` skipped the comparison). The pipeline always passed them, so this was latent. | Mandatory parameters, single overload; blank tool/caller/approver fails closed; the approval hash now covers tool + caller + parameters. | `ConsentEngineToolBindingTests`, `PipelineSecurityTests` | C→G, M |
| A13 | `Policy.cs` `AmsiScanner` | `EnsureInitialized()` ran outside the `try`, so a missing `amsi.dll` threw `DllNotFoundException` out of `Scan`; administrator-blocked results (0x4000–0x4FFF) were treated as clean; no way to fail closed. | Initialization failure is a decision; admin-blocked is denied; `Amsi:Mode` `BestEffort` (default, behaviour unchanged) or `Strict`. | `AmsiScannerTests`, `PipelineSecurityTests` | R→G (probe), M |
| A14 | `JeaEndpointClient` | `RunspaceFactory.CreateRunspace` was outside the `try`, so a session-setup failure threw out of the pipeline (3 restored tests failed on it off Windows); raw PowerShell error text was placed in the result payload; no WSMan timeouts; every call occupied a thread with no bound. | Creation inside the `try`; fixed reason codes only; open/operation timeouts; the `IJeaExecutor` seam and `BoundedJeaExecutor`. | `JeaEndpointClientFailureTests`, `BoundedJeaExecutorTests` | R→G (3 failures), M |
| A15 | `RateLimiter`, `TaintTracker`, `Transport.cs` | No global rate limit (many callers could collectively exhaust the host); per-caller state never pruned; a denied call still consumed general budget; no cap on in-flight requests, stalled writes, or connections per caller; a client that stopped reading held a pipe slot forever. | Global budget, pruning, deny-consumes-nothing; per-connection in-flight cap; write timeout that tears the connection down; per-caller connection cap. | `TaintTrackerBehaviourTests`, `RateLimiterBehaviourTests`, `TransportSecurityTests`, `TransportResourceLimitTests` | C→G, M |
| A16 | `Get-BrokerNetworkControllerConfig.psm1`, `Get-BrokerJeaEndpoints.psm1` | `Node = $nc.Node` passed an unprojected object graph (a remote call deserializes every property and the broker flattens all of it); `Get-BrokerJeaEndpoints` documented its output as "non-sensitive" while returning `RunAsUser` and `Permission`. | Node projected to names; comment corrected; fields classified. | `NetworkControllerProjectionTests`, `OutputSchemaInventoryTests` | S, M. The real Network Controller cmdlet is **X** |
| A17 | `deploy/setup-wdac.ps1` | The policy was generated from the MCP directory alone: enforced, it would **block Windows itself**. "Enforced" regenerated a policy rather than promoting the audited one, and nothing gated the switch. A first draft of the new gate also had a `TryParse` overload bug that made it throw every time (found only because the function was executed). | Merge with a Windows base policy (refuse without one); promote the saved audit artifact; readiness gate; typed confirmation; Boot Audit on Failure; rollback notes first; never deploys. | `WdacReadinessTests` (22, executed), `DeploymentScriptStaticTests` | R→G for the gate logic. The script end to end, event queries and CiTool: **X** |
| A18 | `test/` | The suite was removed from the tree (see section 2); four restored tests passed vacuously when the fixture file was absent. | Restored; Windows-only tests are explicit skips; CI forbids unexplained skips. | `.github/scripts/check-skips.py` | Script validated locally in all three directions |
| A19 | `Worker.cs`, `Program.cs` | A failed startup self-check stopped the host but **exited 0**, so a service manager saw a clean stop (no recovery action, no alert). | `Environment.ExitCode = 1` on a failed self-check; `Program.cs` returns it. | Checked by running the host (see section 1); no automated test | Executed manually |
| A20 | `Policy.cs` `ParameterValidator.Validate` | A `resourceAllowlist` entry on an **optional** parameter was never checked when the caller left the parameter out, and an entry naming an undefined parameter (a typo) was silently never applied. Neither occurs in the shipped manifest (a test now asserts that), so this was latent. | Both deny. | `ParameterValidatorHardeningTests`, `ShippedManifestInvariantTests` | R→G, M |
| A21 | `Policy.cs`, `Transport.cs` `ParseToolCall` | `unknown-parameter:<name>` echoed an attacker-chosen name (any length, any characters) into the reject reason, the logs and the audit event, and the `toolId` was logged verbatim at any length, so a newline forged log lines. | Plain identifiers only are echoed; `toolId` must match the manifest schema's shape and be at most 100 characters. | `ParameterValidatorHardeningTests`, `TransportSecurityTests` | R→G, M |
| A22 | `Policy.cs` | Bidi overrides (U+202E), zero-width characters, byte-order marks and line/paragraph separators passed the control-character rule, so a value could read differently to a human approver than to the machine. Only parameters with permissive patterns are exposed (the write tools use ASCII-only patterns). | Rejected by Unicode category. | `ParameterValidatorHardeningTests` | R→G, M |
| A23 | `JeaConfigGenerator.cs` | Manifest identifiers (cmdlet, parameter names, gMSA, endpoint) were interpolated **unescaped** into the `.psrc`/`.pssc` files that decide what JEA exposes; `RoleCapabilityName` was used as a file name; ranges were culture-formatted; and a file left by a removed tool would be registered by `register-jea.ps1` with the rest. The manifest is operator-authored and integrity-checked, so this needs a bad edit rather than an outside attacker. | All identifiers validated before anything is written; invariant formatting; stray generated files refused (nothing is deleted). | `JeaConfigGeneratorInputTests` | R→G (30 failures), M |
| A24 | `Program.cs`, `Worker.cs`, `Transport.cs` | Ten settings used `TryParse(...) ? n : default`, so a typo silently changed a security bound (`RequireDistinctApprover: "yes"` became false). | `ConfigReader`: absent key = default, invalid value = startup refused (exit 1) naming the key. The pipe servers validate every setting before listening. | `ConfigurationStrictnessTests` | C→G, M. Real host executed with five invalid values |

### 3.2 Hardening (no specific vulnerability claimed)

- `PipePrincipals` refuses broad principals (Everyone, Authenticated Users, Anonymous, BUILTIN\Users,
  Domain Users/Guests/Computers, ...) and malformed SIDs as pipe clients (ASCII-only SID syntax).
- The validator rejects `null` and any control character for every parameter, because .NET's `$` anchor
  matches before a trailing newline.
- An approval is bound to correlation id, tool, and a hash of tool + caller + parameters.
- `ParameterTypes`, `AmsiMode`, `JeaExecutionLimits` and every numeric config value are validated at
  startup; an unparsable value stops the service.
- Read-tier output inventory (`docs/read-tier-output-inventory.md`) with checks that every wrapper uses an
  explicit projection, emits no credential or key material, executes no dynamic code, and invokes only the
  external executables its manifest entry allowlists.

## 4. Hypotheses from the supplied review

| Claim | Result |
|---|---|
| Documented tests are absent | Absent from the tree, but deleted deliberately and recoverable from history. Restored. |
| `TaskPath` pattern is wrong | True, for different reasons than stated (A2). |
| `ConsentEngine.Verify` tool id is optional | True and fixed (A12); the pipeline always supplied it. |
| `ArgvBuilder` can throw uncaught `FormatException` | True; root cause was validator/converter disagreement (A1). |
| `CaptureCallerSid` swallows exceptions | **Not true**; a blank SID was the real issue (A10). |
| AMSI fails open | True by design; now explicit and configurable. It also threw when `amsi.dll` was missing (A13). |
| Taint is caller-level and coarse | True, and it also had ordering gaps (A6). Still caller-level; see 7. |
| No global rate/resource limits | True (A15). |
| `register-jea.ps1` unregister/register race | Plausible deploy-time window; **not changed**, listed in 7. |
| Read-tier leakage | One real instance (A16); the rest is documented, not a vulnerability (see inventory). |

## 5. Verified correct, no change needed

Read and tested: the P0 fix (the approver identity on the same-pipe reply path is the connection's own
SID; `ForgedDecidedBySidInReplyIsIgnoredAndRealCallerSidIsUsed`); unconditional self-approval refusal;
server-generated correlation ids; argv-only invocation with no composed command string; the untrusted-source
gate running before elicitation with no override; signature re-check on every call; frame length bounds;
the manifest integrity check failing closed.

### Original P0 (kept for the record)

`ParseElicitationReply` once read an optional `decidedBySid` from the reply JSON and used it as the
approver, so a caller could approve its own write by claiming another SID. It now always uses the
connection's impersonated SID. Authorization must never rely on an identity claim in a message body.

## 6. Test inventory

572 tests in `test/Broker.Tests`. Counts by area (one Linux run; CI is the record):

| Area | Test classes | Tests |
|---|---|---|
| Approval, consent, router | `ConsentEngineTests`, `ConsentEngineToolBindingTests`, `ElicitationRouterTests`, `ElicitationRouterBindingTests`, `ApprovalPipeServeTests` | 42 |
| Pipeline gates and fail-closed behaviour | `PipelineSecurityTests`, `BrokerPipelineTests` | 63 |
| Parameters, types, paths | `ParameterValidatorTests`, `ParameterValidatorHardeningTests`, `TypedParameterTests`, `TaskPathValidationTests`, `UntrustedSourceGateTests` | 131 |
| Transport, identity, configuration | `TransportIntegrationTests`, `TransportSecurityTests`, `TransportResourceLimitTests`, `PipePrincipalTests`, `McpFramingTests`, `ConfigReaderTests`, `ServerConfigurationValidationTests`, `WindowsPipeIdentityTests` (W) | 118 |
| Limits, taint, AMSI | `BoundedJeaExecutorTests`, `JeaEndpointClientFailureTests`, `TaintTrackerBehaviourTests`, `TaintTrackerTests`, `RateLimiterBehaviourTests`, `RateLimiterTests`, `AmsiScannerTests` | 70 |
| Manifest and registry | `ManifestStoreHardeningTests`, `ManifestStoreRevocationTests`, `ManifestIntegrityTests`, `ManifestTierHardeningTests`, `ShippedManifestInvariantTests`, `CorrelationLogTests`, `SignatureVerifierRealFileTests` (W) | 45 |
| JEA configuration and wrappers | `JeaConfigGeneratorTests`, `JeaConfigGeneratorInputTests`, `JeaEndpointClientSerializationTests`, `OutputSchemaInventoryTests`, `WrapperHygieneTests`, `NetworkControllerProjectionTests` (S) | 71 |
| Deployment scripts | `WdacReadinessTests` (executed PowerShell), `DeploymentScriptStaticTests` (parse + AST) | 29 |
| Workflows | `WorkflowTests` | 3 |

(W) = Windows-only tests present in that class, skipped here. (S) = static analysis of source text.

## 7. Remaining risks and limitations

- **Not verified end to end.** WSMan loopback into a real registered JEA endpoint; gMSA/Kerberos and
  delegation; a real pipe ACL refusing a *different* principal (the Windows tests use a same-user client);
  AMSI with a real provider; every wrapper's output against a real AD/DNS/DHCP/Hyper-V/IIS/etc. role; WDAC
  enforcement and rollback; the Windows CI job and `WindowsPipeIdentityTests`. These need a domain-joined
  Windows Server test environment.
- **`PowerShell.Stop()` is best effort.** A timeout is reported as `jea-timeout` (outcome unknown) and the
  slot stays occupied until the call returns. A call blocked in `Runspace.Open()` cannot be interrupted;
  the WSMan open timeout bounds it. Treat a timeout or disconnect as an uncertain outcome.
- **Taint is per caller, not per value.** It cannot tell which later parameter came from which earlier
  output. Many read tools return free text that others can author (VM, service, task and share names) and
  are deliberately **not** tagged untrusted, because tagging would block the list-then-act workflow for
  five minutes after every read. The human approver, who now sees the parameters, is the control. A new
  such tool must record this decision or the inventory test fails. Provenance-aware taint would be the real
  fix and is not attempted.
- **AMSI is supplementary.** In `BestEffort` mode a host without a provider gets no AMSI protection.
- **Manifest integrity is a hash, not a signature.** An attacker who can write both the manifest and its
  sidecar defeats it. Protect both with NTFS ACLs; prefer a signed manifest.
- **Local logs are not tamper-proof.** ETW, transcripts and the correlation log need forwarding to an
  independent collector.
- **Reparse-point and denylist checks in `Get-BrokerListDirectory`** are lexical and not race-resistant.
- **`register-jea.ps1`** unregisters then registers an endpoint; during that window the endpoint is absent.
  Not changed here.
- **`jea/generated` contains 51 stale tracked files** although the directory is git-ignored. Regenerate;
  never deploy them as-is.
- **Free-text fields** such as `Description` and names are returned as written; they are classified in the
  inventory but not sanitized.
- **The approver's view is only as good as the approver's client.** The broker now sends the validated
  parameters; no approver UI exists in this repository.

## 8. Breaking changes and migration

- `ConsentEngine.Verify` requires `expectedToolId` and `replyToolId` (compile error for old callers).
  `ConsentEngine.HashOperation` replaces `HashParameters` in the pipeline; an approver client that
  recomputed the old hash must be updated (it echoes the hash it was sent, so a client that does not
  recompute is unaffected).
- `ElicitationContext` and `PendingElicitation` gained an optional `Parameters`; the approval and
  elicitation request frames gained `parameters` (and `toolId` on the same-pipe frame).
- `BrokerPipeline` takes an `IJeaExecutor`; `JeaEndpointClient` is wrapped by `BoundedJeaExecutor` in
  `Program.cs`. `JeaEndpointClient`'s constructor gained an optional options argument.
- `RateLimiter` and `TaintTracker` constructors gained optional parameters (global limit, clock).
- Behaviour: write tools with `requiresElicitation: false` now ask for approval; manifest tools with an
  unrecognized tier are not registered; hot reload no longer applies additions or loosening; new defaults
  apply (global 600 calls/min, 8/4/2 JEA concurrency, 16 in-flight per connection, 4 connections per
  caller, 10 s write timeout). JSON `true`/`false` parameters are now accepted as `"true"`/`"false"`.
  The wrapper `Get-BrokerNetworkControllerConfig` returns node names instead of node objects. Wrappers
  must be re-signed after these edits.
- Operators will notice: a bad setting now stops the service (exit code 1, key named) where it used to fall
  back to a default, so review `appsettings.json` and any environment overrides before upgrading; a failed
  startup self-check exits 1 instead of 0; `generate-jea` refuses a manifest with a non-identifier value, an
  output directory holding generated files that are not in the manifest, or `useGmsa` without a
  `gmsaAccount`; a tool id that is not `^[a-z0-9]+(-[a-z0-9]+)*$` is a malformed request; a
  `resourceAllowlist` entry on an optional or undefined parameter denies the call.
- Operators: regenerate the manifest sidecar after any manifest edit; set `Amsi:Mode` deliberately; review
  the new `Jea:Limits:*` and `Pipe:*` defaults for the expected load.

## 9. Readiness

Ready for review. **Not ready for production use of the write tools.** The pieces that carry the trust
decision (WSMan/JEA execution, gMSA identity, real ACL enforcement, WDAC) have no test coverage here and
need the Windows Server integration matrix in `docs/security-hardening.md` to pass first.

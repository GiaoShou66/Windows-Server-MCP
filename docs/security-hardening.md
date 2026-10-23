# Security Hardening Guide

## Installation and service identity

- Run the broker under a dedicated gMSA only when domain access is required.
- Use a virtual account for local-only read tools.
- Do not use Domain Admin or Local Administrator as the broker identity.
- Restrict the published executable, manifest, wrapper modules, generated JEA files,
  transcript directory, and correlation log to administrators, the service identity,
  and the required Windows service infrastructure.
- Keep the MCP client SID allowlist minimal. The broker refuses `Everyone`, `Authenticated Users`,
  `Anonymous`, `BUILTIN\Users`, `Domain Users` and similar broad principals at startup, but a group that
  is merely large is still too broad: name the specific service accounts.

## Manifest and module integrity

- Keep `Manifest:RequireIntegrity` enabled.
- Protect both `policy/manifest.json` and its `.sha256` sidecar with NTFS ACLs.
- Generate the sidecar only in a trusted deployment pipeline. Do not allow the broker
  service identity or MCP client to modify policy files.
  `(Get-FileHash policy\manifest.json -Algorithm SHA256).Hash | Set-Content -NoNewline policy\manifest.json.sha256`
- The hash covers exact bytes, so line endings matter. `.gitattributes` pins the policy files to LF; do not
  override it with `core.autocrlf` rewriting, and verify the hash on the deployed copy, not only in the
  repository. The sidecar is a hash, not a signature: an attacker who can write both files defeats it.
- Hot reload is **narrowing only**. Removing a tool or setting `"revoked": true` takes effect immediately
  (including when the file is replaced by an atomic rename). Anything else (adding a tool, changing a
  tier, parameter or allowlist) takes effect after a restart. If the integrity check fails during a reload
  every tool is revoked, so update the manifest and its sidecar together and expect a brief refusal window
  if you write them one after the other.
- Sign wrapper modules with an approved certificate and verify signatures before
  installation. Editing a wrapper invalidates its signature; re-sign after every change.
- Install each module once in a canonical, ACL-protected module directory. Remove
  shadowed duplicate module versions.
- Generate JEA files from the reviewed manifest, review the diff, and register only the
  generated files from the same deployment. Do not deploy the files tracked under `jea/generated`; they are
  stale snapshots.
- Treat manifest, policy, wrapper modules, role capabilities, and session configurations
  as one versioned release.

## JEA and least privilege

- Use `RestrictedRemoteServer` and `NoLanguage`.
- Expose only the reviewed wrapper cmdlet for each role capability.
- Keep `VisibleExternalCommands` empty unless a specific wrapper requires an explicitly
  reviewed executable. A test checks that a wrapper invokes only the executables its manifest entry lists.
- Use gMSA only for tools that require domain/network identity.
- Verify effective role definitions and run-as identity with a low-privilege test account.
- Test prohibited commands and alternate parameter forms, not only successful calls.
- Do not provide an arbitrary PowerShell or script execution tool.
- Review what each read tool returns: `docs/read-tier-output-inventory.md` lists every field and its
  sensitivity. Some tools return text that others can author (VM, service and task names); see
  "Prompt injection" below.

## Approval and operations

- Keep `Elicitation:RequireDistinctApprover` enabled for all write/destructive tools. Write tools always
  require approval; the manifest cannot switch it off.
- Configure an explicit `ApproverSids` allowlist and protect the approval pipe with its
  own ACL. The ACL also admits the service's own identity; the broker ignores replies from any SID not in
  `ApproverSids`.
- Never derive an approver (or any authorization-relevant) identity from a field inside a
  client-supplied message body. Use only identity obtained from OS-level impersonation of
  the connection itself (e.g. `RunAsClient`). This review found and fixed exactly this
  mistake in the same-pipe elicitation reply path; see `docs/security-audit.md`, "Original P0". If a future
  endpoint or protocol change introduces a new way to signal a decision, audit it for the same pattern
  before shipping it.
- The approval request carries the tool, the caller, the validated parameters and an opaque operation hash
  (SHA-256 over tool + caller + parameters). **An approver client must display the parameters** and must
  not approve on the hash alone. No approver UI ships in this repository.
- Configure explicit `resourceAllowlist` values for every write tool before enabling it.
  Empty resource lists deliberately deny all values, which is why the shipped write tools do nothing until
  an administrator scopes them. Scope every identifying parameter, not just one (for example
  `set-scheduled-task-state` ships with only `TaskPath` scoped; add `TaskName` too).
- Treat a disconnect or timeout as an uncertain execution outcome until the underlying
  PowerShell operation is verified stopped. A `jea-timeout` means the broker stopped waiting and asked for
  cancellation; it does not mean the work stopped.
- Keep rate limits, frame limits, concurrency limits and execution limits conservative. Defaults:
  60 calls/min per caller, 600/min overall, 8 concurrent JEA calls (4 per endpoint, 2 per tool), a queue of
  16 waiting up to 5 s, 60 s execution, 512 KiB response, 16 requests in flight and 4 connections per
  caller. Size them against the host, not against the client.

## Prompt injection and taint

- Taint is per caller and time-boxed (`Taint:WindowSeconds`, default 300). It is checked before a write,
  set before an untrusted-source tool runs (also when it fails), and checked again after a human approves.
  It cannot tell which value came from where.
- Tools whose output is AD data, file names/contents or network responses are tagged and taint the caller.
  Many other read tools return names or descriptions that a lower-privileged party can write. They are
  deliberately not tagged, because tagging them would block "list, then act" for five minutes, and
  the approver's review of the exact parameters is the control. If you want those tools to taint as well,
  add an `untrustedInputSources` entry in the manifest; expect the workflow cost.
- The untrusted-source gate (a tagged tool can never be a write tool) has no approval override.

## AMSI

- AMSI is a second opinion on already-validated arguments, never the validation or the authorization.
- `Amsi:Mode` `BestEffort` (default) logs and continues when AMSI cannot answer. On a host with no AMSI
  provider the layer then does nothing. `Strict` denies the call instead; use it only on hosts where a
  provider is guaranteed, and test it, because a missing provider then stops every call that has parameters.
- Detected or administrator-blocked content is denied in both modes.

## Audit and monitoring

- Protect transcript and correlation-log directories from the MCP client.
- Forward ETW and JEA audit events to an independent collector where possible.
- Retain request ID, caller SID, tool, endpoint, approval decision, execution result,
  duration, and cancellation state.
- Do not log passwords, access tokens, or raw sensitive directory attributes.
- Treat ambiguous transcript correlation as an audit failure requiring investigation,
  not as a successful attribution.
- A failure to write the correlation log after a call has executed is logged as an error and does not hide
  the result. Alert on it.

## WDAC and deployment

`deploy/setup-wdac.ps1` builds policy files and **never deploys one**. It was changed because its earlier
form built a policy from the MCP directory alone, which, once enforced, would have blocked Windows itself.

How it works now:

1. **Audit.** `setup-wdac.ps1 -ServerPath <dir> -Mode Audit` scans the MCP directory, merges the result
   into a Windows base policy (`DefaultWindows_Enforced.xml` by default, via `-BasePolicyXml`; the script
   refuses to run without one), sets the Audit option, and saves `audit.xml`, `audit.cip` and
   `audit-state.json` (start time, policy hash, policy id). Running Audit again builds a *new* policy and
   restarts the audit period.
2. **Deploy the audit policy yourself** (`CiTool --update-policy audit.cip`) on a test server first, and let
   it run under realistic load.
3. **Review** `Microsoft-Windows-CodeIntegrity/Operational`, event 3076 ("would have been blocked"), and add
   rules or accept each finding consciously.
4. **Promote.** `setup-wdac.ps1 -Mode Enforced -ConfirmEnforcement "ENFORCE <COMPUTERNAME>"` does not rebuild
   anything: it takes the saved `audit.xml` (same policy id, same rules) and removes only the Audit option,
   after `Test-WdacEnforcementReadiness` confirms: an audit state exists and is `Audit`; `audit.xml` is
   unchanged since; at least `-MinAuditDays` (default 7) have passed; no unreviewed 3076 events; the log
   shows the policy being loaded; and the confirmation text matches exactly. It adds "Boot Audit on Failure"
   so a boot-critical driver the audit missed degrades to audit mode, and writes `ROLLBACK.txt` first.
5. **Deploy the enforced policy yourself** and keep out-of-band console access until the server has been
   restarted and verified.

Overrides exist (`-AcceptShortAudit`, `-AcceptAuditFindings`, `-AssumeAuditPolicyActive`) and are recorded in
`enforced-state.json`. An unreadable event log, a changed policy, a missing state file, a wrong
confirmation, or an unreadable start time cannot be overridden.

What this does **not** establish, and what has **not** been tested: the readiness *decision* is unit-tested
(22 tests executed through the PowerShell engine), but `New-CIPolicy`, `Merge-CIPolicy`, the event-log
queries (IDs 3076 and 3099 and the message match), `CiTool` and the rollback steps need a Windows host and
have not been run. The audit period cannot prove the audit exercised every workload, and nothing here proves
the server will boot or run its services under enforcement. The rollback notes assume an unsigned policy
(which this script builds); a signed policy cannot be removed that way.

General sequence for any change:

1. Generate and review JEA files.
2. Install signed modules into the canonical directory.
3. Run the broker and wrapper self-checks in a test environment.
4. Deploy WDAC in Audit mode and inspect observed events.
5. Test normal operation and all required-deny cases.
6. Capture a rollback copy of manifest, modules, JEA files, and service configuration.
7. Enable Enforcement only after the rollback path has been tested.

If any signature, manifest integrity, JEA registration, or self-check fails, stop the
deployment. Do not fall back to unrestricted PowerShell or disable a security gate.

The deployment scripts enforce these requirements: `register-jea.ps1` refuses
missing or unsigned wrapper modules and rejects module roots writable by broad
local principals. `install-service.ps1` rejects unsigned `Broker.Host.exe` and
publish directories writable by `Everyone`, `Authenticated Users`, or
`BUILTIN\Users`. Do not use a developer or temporary publish directory in
production. `register-jea.ps1` unregisters and re-registers an endpoint; the endpoint is absent in between,
so do not run it against a busy production broker.

## Continuous integration

`.github/workflows/ci.yml` builds and tests on a Windows runner (everything, **zero skips allowed**) and on
Linux (the cross-platform subset; the only skips allowed are tests carrying the "Requires Windows" reason).
The Linux job does not test any Windows-only property: pipe ACLs, impersonation, WinVerifyTrust, AMSI, WSMan.
The workflow definition has not been run by the author of this revision.

## Required integration environment

Before production use, test on isolated Windows Server hosts with the supported roles:
AD DS, DNS/DHCP, IIS, Hyper-V, and local-only Server Manager tools. Include a domain
joined gMSA host, a low-privilege caller, a separately authorized approver, and register the endpoints.
The following are **not covered by any test in this repository** and each needs a pass/fail record:

| Check | Why it matters |
|---|---|
| A caller outside `Pipe:AllowedSids` is refused by the real pipe ACL; the same for the approval pipe | Only a same-user client is exercised by `WindowsPipeIdentityTests` |
| Loopback WSMan into each registered JEA endpoint runs the mapped cmdlet and nothing else | The execution boundary itself |
| The gMSA authenticates to AD and DNS/DHCP/etc. as expected (Kerberos, no double hop) | All directory tools |
| Each wrapper's real output matches `docs/read-tier-output-schemas.json` for the role | Today this is source analysis only |
| Cancellation and timeout: does `PowerShell.Stop()` actually stop the operation, and what state is left | The `jea-timeout` outcome is "unknown" |
| Reparse-point and junction cases for `list-directory-contents` | The wrapper check is lexical and racy |
| AMSI with a real provider, in both modes | `Strict` could stop all parameterized calls |
| WDAC audit → enforce → rollback on a representative server, including a reboot | Untested |
| Atomic-rename revocation on Windows | Windows `FileSystemWatcher` semantics differ from Linux |
| Re-signed wrappers load under the generated `.pssc` | Wrappers changed in this revision |

Never run these tests against an unapproved production domain.

# Windows-Server-MCP Security Audit

## Scope and evidence

This review covers the broker request path, manifest loading, policy gates, elicitation,
JEA invocation, deployment module installation, transcript correlation, and the available
.NET tests. Local tests run on Windows without a domain controller or registered production
JEA endpoint. Claims about gMSA, Kerberos, Named Pipe ACL enforcement, WDAC enforcement,
and installed Windows Server roles therefore remain integration-test assumptions.

## Request path

1. `NamedPipeServer` captures the caller SID from the pipe token.
2. `BrokerPipeline` loads the tool from `ManifestStore`.
3. The backend signature, taint state, parameters, AMSI result, untrusted-source policy,
   and rate limit are checked in order.
4. Write/destructive tools require elicitation. Production configuration requires the
   separate approval pipe; same-pipe confirmation cannot pass `ConsentEngine`.
5. `ArgvBuilder` creates typed parameters and `JeaEndpointClient` invokes the fixed JEA
   cmdlet.
6. Completion is recorded in ETW and the correlation log; transcript joining rejects
   ambiguous time-window matches.

## Confirmed defects remediated

### P0 — Approval forgery via client-supplied identity field

**File:** `src/Broker.Transport/Transport.cs`, `ParseElicitationReply` (same-pipe elicitation
reply path used by `NamedPipeServer.ServeAsync`).

**Invariant violated:** authorization must never rely on a client-supplied identity claim.
The mission brief for this review states this explicitly; the code violated it directly.

**Defect:** `ParseElicitationReply` read an optional `decidedBySid` field from the
elicitation-reply JSON body and used it as the approver identity whenever present, falling
back to the connection's real impersonated `callerSid` only when the field was absent:

```csharp
var decidedBy = root.TryGetProperty("decidedBySid", out var d) ? d.GetString() ?? callerSid : callerSid;
```

Because the reply travels over the *same pipe connection* the caller itself holds, the
caller fully controls this field. A caller could self-approve any write/destructive call
by sending `approved: true` together with a `decidedBySid` naming any SID other than its
own — defeating `ConsentEngine.Verify`'s unconditional self-approval check, which compares
`decidedBySid` against `callerSid` but has no way to know the former was never
authenticated. The separate distinct-approver pipe (`ApprovalPipeServer`, line ~634 in the
same file) was not affected: it always derives the approver identity from *that* pipe's own
`RunAsClient` impersonation and never reads an identity field from the message body.

**Root cause:** treating a value from the untrusted message body as equivalent to a value
derived from OS-level impersonation, for the specific field the authorization decision
depends on.

**Fix:** removed the client-controllable field entirely. The same-pipe reply path now
always uses the connection's own `callerSid` for `DecidedBySid`, with no override. As a
direct consequence, a same-pipe reply to a write/destructive elicitation will now always
fail `self-approval-forbidden` (`decidedBySid == callerSid` by construction) — same-pipe
mode can no longer approve a mutating call at all, which is the intended effect: mutating
tools require the distinct approval pipe.

**Regression test:** `test/Broker.Tests/TransportIntegrationTests.cs`,
`ForgedDecidedBySidInReplyIsIgnoredAndRealCallerSidIsUsed`. Verified failing against the
original code (asserts `DecidedBySid == "REAL-CALLER-SID"`; failed with
`"S-1-5-21-FORGED-DISTINCT-APPROVER"` before the fix) and passing after.

**Severity:** P0. No special privilege or network position is required — any MCP client
already connected to the main pipe (the normal, expected caller) could exploit this using
only a message it was already permitted to send. This was the single most severe finding
in this review; it would have let any caller bypass the entire human-approval control the
system's threat model depends on.

### Manifest integrity

The registry previously deserialized a hot-reloaded manifest without checking its content.
The registry now supports a required SHA-256 sidecar and fails closed with an empty active
registry when the sidecar is missing or does not match. The deployed configuration enables
this check and includes `policy/manifest.json.sha256`.

This is an integrity check, not signer authentication. The sidecar and manifest must be
protected by NTFS ACLs and changed only by trusted deployment automation. A signed manifest
or authenticated deployment service is recommended for production.

### Self-approval

`ConsentEngine` now rejects caller/approver SID equality unconditionally. Distinct
approver mode is enabled by default. The approval pipe must be ACL-restricted to the
configured approver SIDs.

### Cancellation

`JeaEndpointClient` registers cancellation handling that calls `PowerShell.Stop()` and
returns an explicit `jea-cancelled` failure result when cancellation is observed. The
effectiveness of stopping individual Windows Server cmdlets requires an integration test
on the supported JEA/WSMan configuration.

### Module deployment consistency

The JEA registration script now compares the SHA-256 hash of each source wrapper module
with the installed destination file and aborts on mismatch. The source and destination
directories must still be ACL-protected, and duplicate module names must not be present
in the effective PowerShell module search path.

### Transcript correlation

Transcript aggregation no longer selects an arbitrary first match. A unique endpoint/time
match is required; multiple candidates are logged as ambiguous and are not attributed to
any caller or tool.

### Approval expiry and operation binding

Approval resolution now atomically checks the pending entry's expiry, correlation ID,
tool ID, and parameter hash before completing the waiting operation. A mismatched or
expired reply is rejected and cannot win the timeout race. The pipeline also verifies the
tool ID carried by the approval reply.

### Resource scope

Tool manifests support `resourceAllowlist` entries keyed by parameter name. The broker
rejects a supplied resource value that is not listed. The shipped write tools currently
have empty scope lists intentionally, so they remain unavailable until an administrator
provides explicit resource identifiers and refreshes the manifest integrity sidecar.

### Reparse-point defense

The directory wrapper rejects reparse points in the requested path before enumeration.
This reduces junction/symbolic-link traversal risk, but it is not a complete race-resistant
filesystem sandbox; NTFS ACLs and an isolated Windows filesystem test remain required.

## Regression tests

The test suite covers manifest integrity success/failure, self-approval rejection,
transport elicitation behavior, policy gates, signature verification, JEA serialization,
transcript/correlation logging, and workflow aggregation.

Last local run:

```text
dotnet test .\mcp-broker.sln --no-restore
Passed: 82
Failed: 0
Skipped: 0
```

## Residual risks and required validation

- Deployment now fails closed when wrapper modules or `Broker.Host.exe` are
  unsigned, missing, or stored in locations writable by broad local principals.
  The Broker also verifies that the module resolved through `PSModulePath` for
  JEA has the same content and signer as the manifest-referenced module.
- A SHA-256 sidecar is not an authenticated signature if an attacker can write both files.
- `ModulesToImport` is generated by module name; production deployment must still
  ensure one canonical, ACL-protected module installation path.
- Windows reparse points and junctions require an isolated filesystem test; the directory
  wrapper's lexical checks and denylist are not proof of race-resistant containment.
- `PowerShell.Stop()` requires real JEA tests to establish whether a stopped operation has
  ceased producing side effects.
- gMSA identity, Kerberos delegation, JEA role capabilities, and Named Pipe/Approval Pipe
  ACLs require a domain-joined Windows Server test environment.
- ETW and transcript files need protected retention or forwarding to an independent log
  collector. Local logs alone are not tamper-proof.
- The current taint window is a conservative caller-level approximation, not object-level
  data-flow tracking.

This repository should not be treated as production-ready for high-impact changes until
the Windows Server integration test matrix passes and deployment ACLs are independently
reviewed.

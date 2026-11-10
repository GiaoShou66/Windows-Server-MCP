# Safe AI-Driven Windows Server Configuration Guide

The MCP Broker is a security-hardened, fail-closed gateway with strict OS identity impersonation, Authenticode verification, and JEA endpoint boundaries. It is designed so that an AI client runtime (e.g. Claude Desktop, Cursor, Cline, OpenCodeInterpreter) can interact with Windows Server exclusively through standardized Model Context Protocol (MCP) JSON-RPC 2.0 stdio framing, while strictly preventing the AI from modifying its own trust, policies, or permissions.

---

## 1. Non-Negotiable Invariants & Architecture

1. **Disjoint Caller and Approver Identities (Invariant 1)**:
   - Caller SIDs and Approver SIDs must be strictly disjoint (`CallerSids ∩ ApproverSids == ∅`).
   - The broker service verifies this at startup and refuses to start if there is any overlap.
2. **OS-Enforced Identity Only (Invariant 2)**:
   - No identity, authorization, or policy field is ever accepted from a client JSON message body.
   - All authorization decisions are bound strictly to OS-level named pipe impersonation (`RunAsClient`).
3. **No Broad JEA Access Groups (Invariant 3)**:
   - JEA RoleDefinitions grant access ONLY to a group whose sole member is the broker service account.
   - Broad principals (`BUILTIN\Users`, `Users`, `Domain Users`, `Authenticated Users`, `Everyone`, `Interactive`) are rejected at generation time.
4. **AI-Reachable Surface Cannot Modify Trust (Invariant 4)**:
   - The AI agent cannot modify `manifest.json`, `appsettings.json`, certificates, ACLs, or JEA configurations.
   - `deploy/*.ps1` is operator-only and is never exposed as an MCP tool.
5. **Fail-Closed Gate Pipeline (Invariant 5)**:
   - Unknown risk tiers, missing approvers, untrusted signatures, unwritable audit logs, or stale JEA files cause immediate rejection, never degraded execution.
6. **No Destructive Tools / Reversible Operations (Invariant 6)**:
   - Write tools are reversible toggles on existing objects. No arbitrary script execution or deletion tools exist.

---

## 2. Component Architecture

```
┌─────────────────────────────────┐
│     AI Agent Runtime            │ (Claude Desktop, Cursor, Cline)
│  (Stdio JSON-RPC 2.0 Client)    │
└────────────────┬────────────────┘
                 │ stdin / stdout (JSON-RPC 2.0)
                 ▼
┌─────────────────────────────────┐
│   Broker.McpAdapter (Stdio)     │ -> Translates JSON-RPC 2.0 to Broker Named Pipe Protocol
└────────────────┬────────────────┘
                 │ \\.\pipe\McpBroker (OS Named Pipe Impersonation)
                 ▼
┌─────────────────────────────────┐       \\.\pipe\McpBroker.Approvals
│   Broker.Host (Worker Service)  │ ◄──────────────────────────────────┐
│   8-Gate Fail-Closed Pipeline   │                                    │
└────────────────┬────────────────┘                       ┌────────────┴─────────────┐
                 │                                        │   Broker.ApproverCli     │
                 │ JEA PowerShell Session                 │ (Human-in-the-Loop CLI)  │
                 ▼                                        └──────────────────────────┘
┌─────────────────────────────────┐
│ Windows Server 2025 Subsystems  │
│ (AD DS, Hyper-V, IIS, Services) │
└─────────────────────────────────┘
```

---

## 3. MCP JSON-RPC 2.0 Stdio Adapter (`Broker.McpAdapter`)

The `Broker.McpAdapter` binary provides the standard stdio JSON-RPC 2.0 interface expected by MCP-compliant AI agent hosts.

### Usage in Client Config (e.g. `claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "windows-server": {
      "command": "C:\\McpBroker\\Broker.McpAdapter.exe",
      "args": [
        "--pipe", "McpBroker",
        "--manifest", "C:\\McpBroker\\policy\\manifest.json"
      ]
    }
  }
}
```

### Protocol Operations Supported:
- `initialize`: Returns server info (`windows-server-mcp`), capabilities (`tools`), and protocol version (`2024-11-05`).
- `notifications/initialized`: Notification handshake.
- `tools/list`: Dynamically enumerates active tools from `policy/manifest.json`, formatting input schemas compliant with JSON Schema draft-07. Free-text tools carry `"untrustedInputSources": ["host-metadata"]`.
- `tools/call`: Translates standard MCP `{ name, arguments }` into named-pipe requests, dispatches across the 8-gate broker pipeline, and formats responses as MCP text content or error diagnostics.

---

## 4. Human-in-the-Loop Approver CLI (`Broker.ApproverCli`)

All write-tier tools require out-of-band authorization from a human operator possessing an authorized Approver SID.

### Usage:
```powershell
# Run under authorized human approver account:
Broker.ApproverCli.exe --pipe McpBroker.Approvals
```

### Interactive Approval Workflow:
When an AI agent requests a write operation (e.g. `set-broker-scheduled-task-state` or `set-broker-gpo-status`), the broker pauses dispatch and broadcasts the request to `Broker.ApproverCli`:
```
================================================================================
                         [PENDING APPROVAL REQUEST]
================================================================================
CorrelationId:  3d489b88-1249-410a-b283-93bb3644917a
Tool ID:        set-broker-scheduled-task-state
Caller SID:     S-1-5-21-1286530945-682254993-2698348803-1001
Expires (UTC):  2026-11-10 12:45:00Z
Parameters:
  TaskName            : BackupDatabase
  TaskPath            : \Microsoft\Windows\DataProtection
  Enabled             : true
================================================================================
Authorize execution? [y/N]: y
[approver-cli] Decision submitted: APPROVED
```

---

## 5. Operator-Only Setup Engine (`deploy/auto-configure.ps1`)

`deploy/auto-configure.ps1` is strictly for human operators setting up the host.

### Modes:
1. **Discover (`-Discover`)**: Emits structured JSON regarding host OS, domain status, active features, and certificates.
2. **Plan (`-Plan`)**: Formulates deployment profile.
   - In production mode, an enterprise CA code-signing certificate thumbprint is required (`-CertThumbprint`).
   - Rejects broad access groups and enforces caller/approver disjointness.
3. **Apply (`-Apply`)**: Configures broker service settings and stages modules. In production mode, the integrity sidecar must match off-host release artifacts.
4. **Validate (`-Validate`)**: Evaluates all 7 security gates, WinVerifyTrust module signatures, ACL protections, and JEA endpoints.

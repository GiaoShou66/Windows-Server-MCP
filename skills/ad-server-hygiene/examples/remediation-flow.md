# Golden Sample — Controlled Drift Remediation & Approver Card Workflow

**Scenario.** This continues `examples/audit-session.md`. The operator has
approved containment items R-01 (`helpdesk2`) and R-02
(`\OneDriveSyncHealthCheck`). Later they ask to restore the intranet site and
make an out-of-bounds request. The transcript shows the full safe write loop:

**re-read → propose with rollback → dispatch → human approves in
Broker.ApproverCli → verify → report**, plus a denied card, an expired card,
and a hard-boundary refusal.

Two terminals are involved:

- **Agent session** — the MCP client (Claude Desktop, Cursor, Cline, …)
  talking to `Broker.McpAdapter`.
- **Approver terminal** — a separate human operator running
  `Broker.ApproverCli.exe --pipe McpBroker.Approvals` under an identity that is
  in the approver group and is **not** the caller identity.

All names and identifiers are synthetic.

---

### Turn 1 — Operator

> Go ahead with R-01 and R-02.

### Turn 1 — Agent

Before any write I re-read current state, so the action targets exactly what
exists now rather than what existed at audit time.

```json
{ "name": "list-local-users", "arguments": {} }
```
```json
[
  { "Name": "Administrator",      "Enabled": false, "LastLogon": "2025-02-11T10:00:00Z", "PasswordExpires": null },
  { "Name": "Guest",              "Enabled": false, "LastLogon": null,                   "PasswordExpires": null },
  { "Name": "DefaultAccount",     "Enabled": false, "LastLogon": null,                   "PasswordExpires": null },
  { "Name": "WDAGUtilityAccount", "Enabled": false, "LastLogon": null,                   "PasswordExpires": "2026-12-30T00:00:00Z" },
  { "Name": "helpdesk2",          "Enabled": true,  "LastLogon": "2026-11-08T02:13:55Z", "PasswordExpires": null }
]
```

State is unchanged since the audit: `helpdesk2` is still `Enabled: true`.

**Proposed change R-01**

| Field | Value |
|---|---|
| Tool | `set-local-user-enabled` |
| Parameters | `UserName = "helpdesk2"`, `Enabled = "false"` |
| Why | Local account in BUILTIN\Administrators with explicit `SeImpersonatePrivilege` and authored persistence (F-01 – F-03) |
| Impact | `helpdesk2` can no longer log on. Existing sessions are not terminated by this action. |
| Rollback | `set-local-user-enabled {UserName: "helpdesk2", Enabled: "true"}` |
| Verify | `list-local-users` → `helpdesk2 Enabled: false` |

```json
{ "name": "set-local-user-enabled", "arguments": { "UserName": "helpdesk2", "Enabled": "false" } }
```

> Action card dispatched to `\\.\pipe\McpBroker.Approvals`. Please review and authorize by pressing [y] in the Broker.ApproverCli terminal.

The card shows tool `set-local-user-enabled`, `UserName: helpdesk2`,
`Enabled: false`, and expires in 120 seconds. It must be approved by an
identity other than the one running this agent session. It will also show
`Caller taint: YES`, because I have just read host metadata with
`list-local-users`. That is expected; it is the approver's cue to check the
account name against their own records rather than against my output.

#### Approver terminal

```text
[approver-cli] Connecting to approval pipe '\\.\pipe\McpBroker.Approvals' as approver SID: S-1-5-21-3623811015-3361044348-30300820-1187
[approver-cli] Connected. Waiting for authorization requests from MCP Broker...

================================================================================
                         [PENDING APPROVAL REQUEST]
================================================================================
CorrelationId:  9f2c41d76b3e4c8aa1f052e7d93b0c64
Tool ID:        set-local-user-enabled
Caller SID:     S-1-5-21-3623811015-3361044348-30300820-1240
Caller taint:   YES - read untrusted data recently; verify the target yourself
Expires (UTC):  2026-11-11 09:14:32Z
Parameters:
  UserName            : helpdesk2
  Enabled             : false
================================================================================
Authorize execution? [y/N]: y
[approver-cli] Decision submitted: APPROVED (Tool: set-local-user-enabled, CorrelationId: 9f2c41d76b3e4c8aa1f052e7d93b0c64)
```

#### Agent session — tool result

```json
{ "Name": "helpdesk2", "Enabled": false }
```

Verifying independently with a fresh read rather than trusting the write
result:

```json
{ "name": "list-local-users", "arguments": {} }
```
```json
[
  { "Name": "Administrator",      "Enabled": false, "LastLogon": "2025-02-11T10:00:00Z", "PasswordExpires": null },
  { "Name": "Guest",              "Enabled": false, "LastLogon": null,                   "PasswordExpires": null },
  { "Name": "DefaultAccount",     "Enabled": false, "LastLogon": null,                   "PasswordExpires": null },
  { "Name": "WDAGUtilityAccount", "Enabled": false, "LastLogon": null,                   "PasswordExpires": "2026-12-30T00:00:00Z" },
  { "Name": "helpdesk2",          "Enabled": false, "LastLogon": "2026-11-08T02:13:55Z", "PasswordExpires": null }
]
```

**R-01 verified.** `helpdesk2` is `Enabled: false`.

Moving to R-02. Re-reading tasks first:

```json
{ "name": "list-scheduled-tasks", "arguments": {} }
```
```json
[
  { "TaskName": "ScheduledDefrag",         "TaskPath": "\\Microsoft\\Windows\\Defrag\\", "State": "Ready", "Author": "Microsoft Corporation" },
  { "TaskName": "Contoso-NightlyReport",   "TaskPath": "\\Contoso\\",                     "State": "Ready", "Author": "CONTOSO\\svc_reporting" },
  { "TaskName": "OneDriveSyncHealthCheck", "TaskPath": "\\",                              "State": "Ready", "Author": "CONTOSO-APP01\\helpdesk2" }
]
```

**Proposed change R-02**

| Field | Value |
|---|---|
| Tool | `set-scheduled-task-state` |
| Parameters | `TaskPath = "\"` (root, exactly as returned), `TaskName = "OneDriveSyncHealthCheck"`, `Enabled = "false"` |
| Why | Persistence mechanism authored by the rogue account (F-03) |
| Impact | Task stops triggering. The task definition and its action binary stay in place for forensics. |
| Rollback | `set-scheduled-task-state {TaskPath: "\\", TaskName: "OneDriveSyncHealthCheck", Enabled: "true"}` |
| Verify | `list-scheduled-tasks` → `State: Disabled` |

```json
{ "name": "set-scheduled-task-state", "arguments": { "TaskPath": "\\", "TaskName": "OneDriveSyncHealthCheck", "Enabled": "false" } }
```

> Action card dispatched to `\\.\pipe\McpBroker.Approvals`. Please review and authorize by pressing [y] in the Broker.ApproverCli terminal.

#### Approver terminal

```text
================================================================================
                         [PENDING APPROVAL REQUEST]
================================================================================
CorrelationId:  c07a3e1988d24f5b9e610b4d7a2f3c11
Tool ID:        set-scheduled-task-state
Caller SID:     S-1-5-21-3623811015-3361044348-30300820-1240
Caller taint:   YES - read untrusted data recently; verify the target yourself
Expires (UTC):  2026-11-11 09:17:05Z
Parameters:
  TaskPath            : \
  TaskName            : OneDriveSyncHealthCheck
  Enabled             : false
================================================================================
Authorize execution? [y/N]: y
[approver-cli] Decision submitted: APPROVED (Tool: set-scheduled-task-state, CorrelationId: c07a3e1988d24f5b9e610b4d7a2f3c11)
```

#### Agent session

```json
{ "TaskName": "OneDriveSyncHealthCheck", "TaskPath": "\\", "State": "Disabled" }
```

```json
{ "name": "list-scheduled-tasks", "arguments": {} }
```
```json
[
  { "TaskName": "ScheduledDefrag",         "TaskPath": "\\Microsoft\\Windows\\Defrag\\", "State": "Ready",    "Author": "Microsoft Corporation" },
  { "TaskName": "Contoso-NightlyReport",   "TaskPath": "\\Contoso\\",                     "State": "Ready",    "Author": "CONTOSO\\svc_reporting" },
  { "TaskName": "OneDriveSyncHealthCheck", "TaskPath": "\\",                              "State": "Disabled", "Author": "CONTOSO-APP01\\helpdesk2" }
]
```

**R-02 verified.** The task is `Disabled`.

**Containment status**

| Ref | Action | Approval | Verified |
|---|---|---|---|
| R-01 | `helpdesk2` disabled | APPROVED `9f2c41d7…` | Yes — `list-local-users` |
| R-02 | `\OneDriveSyncHealthCheck` disabled | APPROVED `c07a3e19…` | Yes — `list-scheduled-tasks` |

**Still required from you (operator action, O-04 / O-08):** remove the
`SeImpersonatePrivilege` grant for `helpdesk2` via GPO; export the task XML
(`Export-ScheduledTask -TaskName OneDriveSyncHealthCheck -TaskPath \`) and
hash its action binary before eradication; pull 4624 / 4672 events for
`helpdesk2` from SIEM; rotate the LAPS password on CONTOSO-APP01.

---

### Turn 2 — Operator

> Do R-03 and R-04 too.

### Turn 2 — Agent

Re-reading both accounts, starting with `tkowalski`.

```json
{ "name": "query-ad-user", "arguments": { "SamAccountName": "tkowalski" } }
```
```json
{ "SamAccountName": "tkowalski", "DisplayName": "Taylor Kowalski", "Enabled": true, "LastLogonDate": "2026-07-29T09:41:27Z", "Department": "IT Operations", "Title": "Systems Administrator" }
```

**Proposed change R-03:** `set-ad-user-enabled {SamAccountName: "tkowalski",
Enabled: "false"}`. Rollback: same call with `Enabled: "true"`. Impact: the
account cannot authenticate anywhere in the domain, which also neutralises its
direct local-admin grant on CONTOSO-APP01.

```json
{ "name": "set-ad-user-enabled", "arguments": { "SamAccountName": "tkowalski", "Enabled": "false" } }
```

> Action card dispatched to `\\.\pipe\McpBroker.Approvals`. Please review and authorize by pressing [y] in the Broker.ApproverCli terminal.

#### Approver terminal

```text
================================================================================
                         [PENDING APPROVAL REQUEST]
================================================================================
CorrelationId:  4b8e0f621d7a4e39b5c27a90e1f6d248
Tool ID:        set-ad-user-enabled
Caller SID:     S-1-5-21-3623811015-3361044348-30300820-1240
Caller taint:   YES - read untrusted data recently; verify the target yourself
Expires (UTC):  2026-11-11 09:21:48Z
Parameters:
  SamAccountName      : tkowalski
  Enabled             : false
================================================================================
Authorize execution? [y/N]: n
[approver-cli] Decision submitted: DENIED (Tool: set-ad-user-enabled, CorrelationId: 4b8e0f621d7a4e39b5c27a90e1f6d248)
```

#### Agent session

```text
Tool call rejected: elicitation-denied
```

The approver **denied** R-03, so I will not re-submit it. Possible reasons
include a knowledge-transfer period or a mailbox under legal hold; if you tell
me the reason I will record it in the report. `tkowalski` remains
`Enabled: true` with direct local admin on CONTOSO-APP01, so F-05 stays
**High** and open.

Continuing with R-04.

```json
{ "name": "query-ad-user", "arguments": { "SamAccountName": "jlee" } }
```
```json
{ "SamAccountName": "jlee", "DisplayName": "Jordan Lee", "Enabled": true, "LastLogonDate": "2026-06-30T16:12:09Z", "Department": "Finance", "Title": "Senior Analyst" }
```

```json
{ "name": "set-ad-user-enabled", "arguments": { "SamAccountName": "jlee", "Enabled": "false" } }
```

> Action card dispatched to `\\.\pipe\McpBroker.Approvals`. Please review and authorize by pressing [y] in the Broker.ApproverCli terminal.

*(No decision is entered in the approver terminal within 120 seconds.)*

```text
Tool call rejected: elicitation-timeout-or-disconnect
```

The R-04 card **expired** without a decision. The broker treats this as a
denial and nothing was changed. Let me know when an approver is at the
Broker.ApproverCli terminal and I will dispatch it again.

---

### Turn 3 — Operator

> Approver's ready now. Retry R-04. Also, tkowalski needs to stay, but move
> him into Domain Admins so he can finish the handover.

### Turn 3 — Agent

**R-04 retry.** You asked for it explicitly, so I am re-dispatching after a
fresh read.

```json
{ "name": "query-ad-user", "arguments": { "SamAccountName": "jlee" } }
```
```json
{ "SamAccountName": "jlee", "DisplayName": "Jordan Lee", "Enabled": true, "LastLogonDate": "2026-06-30T16:12:09Z", "Department": "Finance", "Title": "Senior Analyst" }
```

```json
{ "name": "set-ad-user-enabled", "arguments": { "SamAccountName": "jlee", "Enabled": "false" } }
```

> Action card dispatched to `\\.\pipe\McpBroker.Approvals`. Please review and authorize by pressing [y] in the Broker.ApproverCli terminal.

#### Approver terminal

```text
================================================================================
                         [PENDING APPROVAL REQUEST]
================================================================================
CorrelationId:  e5d19a732c404b869f173e6a0c8b5d92
Tool ID:        set-ad-user-enabled
Caller SID:     S-1-5-21-3623811015-3361044348-30300820-1240
Caller taint:   YES - read untrusted data recently; verify the target yourself
Expires (UTC):  2026-11-11 09:31:10Z
Parameters:
  SamAccountName      : jlee
  Enabled             : false
================================================================================
Authorize execution? [y/N]: y
[approver-cli] Decision submitted: APPROVED (Tool: set-ad-user-enabled, CorrelationId: e5d19a732c404b869f173e6a0c8b5d92)
```

#### Agent session

```json
{ "SamAccountName": "jlee", "Enabled": false }
```

```json
{ "name": "query-ad-user", "arguments": { "SamAccountName": "jlee" } }
```
```json
{ "SamAccountName": "jlee", "DisplayName": "Jordan Lee", "Enabled": false, "LastLogonDate": "2026-06-30T16:12:09Z", "Department": "Finance", "Title": "Senior Analyst" }
```

**R-04 verified.** `jlee` is `Enabled: false`.

**Domain Admins request — declined.** I will not propose
`set-ad-group-membership` with `Action: "Add"` for Domain Admins (RID -512).
This is a hard boundary of this skill, and the broker wrapper
`Set-BrokerAdGroupMembership` independently refuses privileged groups and any
`adminCount=1` group. Granting Tier-0 rights to a departing administrator who
already holds unreviewed local admin rights would also widen the exposure
recorded in F-05.

Safer options for the handover:

1. Keep `tkowalski` as-is for a fixed, documented window, then close F-05 when
   the window ends (the approver already denied disabling the account).
2. Have a Tier-0 administrator grant scoped, time-bound access outside the
   broker (for example a PAM / JIT group with a TTL), with change-board
   approval.

---

### Turn 4 — Operator

> Fine. Last thing — the intranet site is down. Bring it back.

### Turn 4 — Agent

Applying SOP 4. First I need to rule out a link to the compromise, so I
re-read the evidence.

```json
{ "name": "list-windows-services", "arguments": {} }
```
```json
[
  { "Name": "W3SVC",   "DisplayName": "World Wide Web Publishing Service",  "Status": "Stopped", "StartType": "Automatic" },
  { "Name": "WAS",     "DisplayName": "Windows Process Activation Service", "Status": "Running", "StartType": "Manual" },
  { "Name": "Spooler", "DisplayName": "Print Spooler",                      "Status": "Running", "StartType": "Automatic" }
]
```

```json
{ "name": "list-iis-sites", "arguments": {} }
```
```json
[
  { "Name": "Contoso-Intranet", "Id": 2, "State": "Stopped", "PhysicalPath": "D:\\inetpub\\intranet", "Bindings": "*:443:intranet.contoso.com", "ApplicationPool": "IntranetPool" }
]
```

```json
{ "name": "list-directory-contents", "arguments": { "Path": "D:\\inetpub\\intranet" } }
```
```json
[
  { "Name": "default.aspx", "FullName": "D:\\inetpub\\intranet\\default.aspx", "IsDirectory": false, "LengthBytes": 18422, "LastWriteTime": "2026-03-04T14:20:11Z" },
  { "Name": "web.config",   "FullName": "D:\\inetpub\\intranet\\web.config",   "IsDirectory": false, "LengthBytes": 3310,  "LastWriteTime": "2026-03-04T14:20:11Z" },
  { "Name": "bin",          "FullName": "D:\\inetpub\\intranet\\bin",          "IsDirectory": true,  "LengthBytes": null,  "LastWriteTime": "2026-03-04T14:20:09Z" }
]
```

```json
{ "name": "list-firewall-rules", "arguments": {} }
```
```json
[
  { "Name": "IIS-WebServerRole-HTTPS-In-TCP", "DisplayName": "World Wide Web Services (HTTPS Traffic-In)", "Direction": "Inbound", "Action": "Allow", "Profile": "Domain" },
  { "Name": "WINRM-HTTP-In-TCP",              "DisplayName": "Windows Remote Management (HTTP-In)",        "Direction": "Inbound", "Action": "Allow", "Profile": "Domain" }
]
```

**Assessment**

- Nothing in the site root has been written since 2026-03-04, and there are no
  new `.aspx` / `.ashx` files. No web-shell indicator in the content directory.
- `WAS` is running, so the W3SVC dependency is satisfied.
- The HTTPS inbound allow rule is present.
- Root cause cannot be confirmed without the System event log. The most
  likely explanation is that W3SVC stopped and the site stopped with it. To
  confirm, run: `Get-WinEvent -LogName System -MaxEvents 50 | Where-Object
  ProviderName -eq 'Service Control Manager'`.
- W3SVC is not on the wrapper denylist, so starting it is within broker scope.

**Proposed change S-01**

| Field | Value |
|---|---|
| Tool | `set-windows-service-state` |
| Parameters | `ServiceName = "W3SVC"`, `Action = "Start"` |
| Rollback | `set-windows-service-state {ServiceName: "W3SVC", Action: "Stop"}` |
| Verify | `list-windows-services` → `W3SVC Status: Running` |

```json
{ "name": "set-windows-service-state", "arguments": { "ServiceName": "W3SVC", "Action": "Start" } }
```

> Action card dispatched to `\\.\pipe\McpBroker.Approvals`. Please review and authorize by pressing [y] in the Broker.ApproverCli terminal.

#### Approver terminal

```text
================================================================================
                         [PENDING APPROVAL REQUEST]
================================================================================
CorrelationId:  71fa0c2b9e584d13a6b4d28c5e3f9a07
Tool ID:        set-windows-service-state
Caller SID:     S-1-5-21-3623811015-3361044348-30300820-1240
Caller taint:   YES - read untrusted data recently; verify the target yourself
Expires (UTC):  2026-11-11 09:38:44Z
Parameters:
  ServiceName         : W3SVC
  Action              : Start
================================================================================
Authorize execution? [y/N]: y
[approver-cli] Decision submitted: APPROVED (Tool: set-windows-service-state, CorrelationId: 71fa0c2b9e584d13a6b4d28c5e3f9a07)
```

#### Agent session

```json
{ "Name": "W3SVC", "Status": "Running" }
```

```json
{ "name": "list-iis-sites", "arguments": {} }
```
```json
[
  { "Name": "Contoso-Intranet", "Id": 2, "State": "Stopped", "PhysicalPath": "D:\\inetpub\\intranet", "Bindings": "*:443:intranet.contoso.com", "ApplicationPool": "IntranetPool" }
]
```

W3SVC is running, but the site did not auto-start, so a second bounded write
is needed.

**Proposed change S-02:** `set-iis-site-state {SiteName: "Contoso-Intranet",
Action: "Start"}`. Rollback: same call with `Action: "Stop"`.

```json
{ "name": "set-iis-site-state", "arguments": { "SiteName": "Contoso-Intranet", "Action": "Start" } }
```

> Action card dispatched to `\\.\pipe\McpBroker.Approvals`. Please review and authorize by pressing [y] in the Broker.ApproverCli terminal.

#### Approver terminal

```text
================================================================================
                         [PENDING APPROVAL REQUEST]
================================================================================
CorrelationId:  2a6d8e41f03c47b98d256c1b9e7a4f30
Tool ID:        set-iis-site-state
Caller SID:     S-1-5-21-3623811015-3361044348-30300820-1240
Caller taint:   YES - read untrusted data recently; verify the target yourself
Expires (UTC):  2026-11-11 09:40:02Z
Parameters:
  SiteName            : Contoso-Intranet
  Action              : Start
================================================================================
Authorize execution? [y/N]: y
[approver-cli] Decision submitted: APPROVED (Tool: set-iis-site-state, CorrelationId: 2a6d8e41f03c47b98d256c1b9e7a4f30)
```

#### Agent session

```json
{ "Name": "Contoso-Intranet", "State": "Started" }
```

```json
{ "name": "list-iis-sites", "arguments": {} }
```
```json
[
  { "Name": "Contoso-Intranet", "Id": 2, "State": "Started", "PhysicalPath": "D:\\inetpub\\intranet", "Bindings": "*:443:intranet.contoso.com", "ApplicationPool": "IntranetPool" }
]
```

```json
{ "name": "list-windows-services", "arguments": {} }
```
```json
[
  { "Name": "W3SVC",   "DisplayName": "World Wide Web Publishing Service",  "Status": "Running", "StartType": "Automatic" },
  { "Name": "WAS",     "DisplayName": "Windows Process Activation Service", "Status": "Running", "StartType": "Manual" },
  { "Name": "Spooler", "DisplayName": "Print Spooler",                      "Status": "Running", "StartType": "Automatic" }
]
```

**S-01 and S-02 verified.** W3SVC is `Running` and `Contoso-Intranet` is
`Started`. Please confirm that `https://intranet.contoso.com` responds from a
client; the broker cannot make HTTP requests.

---

## Session Change Log

| # | Time (UTC) | Tool | Parameters | Approval | CorrelationId | Result | Verified by |
|---|---|---|---|---|---|---|---|
| 1 | 09:12 | `set-local-user-enabled` | `UserName=helpdesk2`, `Enabled=false` | APPROVED | `9f2c41d76b3e4c8aa1f052e7d93b0c64` | Success | `list-local-users` |
| 2 | 09:15 | `set-scheduled-task-state` | `TaskPath=\`, `TaskName=OneDriveSyncHealthCheck`, `Enabled=false` | APPROVED | `c07a3e1988d24f5b9e610b4d7a2f3c11` | Success | `list-scheduled-tasks` |
| 3 | 09:19 | `set-ad-user-enabled` | `SamAccountName=tkowalski`, `Enabled=false` | DENIED | `4b8e0f621d7a4e39b5c27a90e1f6d248` | No change | — |
| 4 | 09:24 | `set-ad-user-enabled` | `SamAccountName=jlee`, `Enabled=false` | EXPIRED | — | No change | — |
| 5 | 09:29 | `set-ad-user-enabled` | `SamAccountName=jlee`, `Enabled=false` | APPROVED | `e5d19a732c404b869f173e6a0c8b5d92` | Success | `query-ad-user` |
| — | 09:29 | *(refused by agent)* | Domain Admins add for `tkowalski` | — | — | Not proposed — hard boundary | — |
| 6 | 09:36 | `set-windows-service-state` | `ServiceName=W3SVC`, `Action=Start` | APPROVED | `71fa0c2b9e584d13a6b4d28c5e3f9a07` | Success | `list-windows-services` |
| 7 | 09:38 | `set-iis-site-state` | `SiteName=Contoso-Intranet`, `Action=Start` | APPROVED | `2a6d8e41f03c47b98d256c1b9e7a4f30` | Success | `list-iis-sites` |

**Open items:** F-05 (`tkowalski`, denied by approver), R-05
(`svc_legacyftp`, awaiting owner sign-off), R-06 – R-09, and operator actions
O-01 – O-08 from the audit report.

**Rollback bundle** (each requires its own approval card):

```json
[
  { "name": "set-local-user-enabled",    "arguments": { "UserName": "helpdesk2", "Enabled": "true" } },
  { "name": "set-scheduled-task-state",  "arguments": { "TaskPath": "\\", "TaskName": "OneDriveSyncHealthCheck", "Enabled": "true" } },
  { "name": "set-ad-user-enabled",       "arguments": { "SamAccountName": "jlee", "Enabled": "true" } },
  { "name": "set-iis-site-state",        "arguments": { "SiteName": "Contoso-Intranet", "Action": "Stop" } },
  { "name": "set-windows-service-state", "arguments": { "ServiceName": "W3SVC", "Action": "Stop" } }
]
```

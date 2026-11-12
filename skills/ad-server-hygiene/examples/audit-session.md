# Golden Sample — Autonomous AD & Server Hygiene Audit

**Scenario.** The operator asks for a full health and hygiene audit of member
server `CONTOSO-APP01` (Windows Server 2022, IIS) and the `contoso.com`
domain. The agent runs read-tier tools only, produces an executive report,
and stages — but does not dispatch — remediation.

All hostnames, accounts, and values below are synthetic.

---

### Turn 1 — Operator

> Run a full AD and server hygiene audit on CONTOSO-APP01 and the contoso.com
> domain. HR says these people left in the last two quarters: `jlee`,
> `mgarcia`, `tkowalski`, `svc_legacyftp`, `rpatel`. Report back with
> severities. Don't change anything yet.

### Turn 1 — Agent

Loading **ad-server-hygiene**. This is a read-only audit: I will run the
inspection chains of all four SOPs and produce a report. No write-tier tools
will be called.

Scope note: the broker has no bulk AD user enumeration tool, so dormant-user
coverage is limited to the five names you supplied plus any domain identities
I find in local groups on CONTOSO-APP01. Computer objects are a full sweep.

**SOP 2 — password and lockout policy**

```json
{ "name": "get-domain-password-policy", "arguments": {} }
```

```json
{
  "MinPasswordLength": 8,
  "MinPasswordAge": "1.00:00:00",
  "MaxPasswordAge": "180.00:00:00",
  "PasswordHistoryCount": 24,
  "ComplexityEnabled": true,
  "ReversibleEncryptionEnabled": false,
  "LockoutThreshold": 0,
  "LockoutDuration": "00:30:00",
  "LockoutObservationWindow": "00:30:00"
}
```

```json
{ "name": "list-fine-grained-password-policies", "arguments": {} }
```

```json
[
  { "Name": "PSO-StandardUsers",   "Precedence": 10, "MinPasswordLength": 12, "ComplexityEnabled": true, "LockoutThreshold": 10 },
  { "Name": "PSO-Tier0-Admins",    "Precedence": 20, "MinPasswordLength": 15, "ComplexityEnabled": true, "LockoutThreshold": 5 },
  { "Name": "PSO-ServiceAccounts", "Precedence": 20, "MinPasswordLength": 20, "ComplexityEnabled": true, "LockoutThreshold": 0 }
]
```

```json
{ "name": "get-local-security-policy", "arguments": {} }
```

```json
{
  "MinimumPasswordAge": "1", "MaximumPasswordAge": "42", "MinimumPasswordLength": "14",
  "PasswordComplexity": "1", "PasswordHistorySize": "24",
  "LockoutBadCount": "5", "ResetLockoutCount": "15", "LockoutDuration": "15"
}
```

Preliminary SOP 2 analysis:

- Domain `LockoutThreshold: 0` — lockout is **disabled** for every account not
  covered by a PSO. Critical.
- Domain `MinPasswordLength: 8` (< 14) and `MaxPasswordAge: 180` days
  (> 90-day house rule). High.
- `PSO-Tier0-Admins` has precedence **20**; `PSO-StandardUsers` has **10**. An
  admin who is also targeted by the standard-users PSO receives the weaker
  policy. High.
- `PSO-Tier0-Admins` and `PSO-ServiceAccounts` tie at precedence 20. Medium.
- `PSO-ServiceAccounts` has `LockoutThreshold: 0`. High (non-admin tier).
- Local SAM policy on CONTOSO-APP01 is compliant.
- PSO `MaxPasswordAge` and `AppliesTo` are not exposed by the broker — not
  verifiable.

**SOP 1 — identity governance**

```json
{ "name": "list-ad-computers", "arguments": {} }
```

```json
[
  { "Name": "CONTOSO-DC01",  "OperatingSystem": "Windows Server 2022 Datacenter", "LastLogonDate": "2026-11-10T22:14:03Z", "Enabled": true },
  { "Name": "CONTOSO-DC02",  "OperatingSystem": "Windows Server 2022 Datacenter", "LastLogonDate": "2026-11-10T21:55:41Z", "Enabled": true },
  { "Name": "CONTOSO-APP01", "OperatingSystem": "Windows Server 2022 Standard",   "LastLogonDate": "2026-11-09T08:02:17Z", "Enabled": true },
  { "Name": "CONTOSO-FS02",  "OperatingSystem": "Windows Server 2016 Standard",   "LastLogonDate": "2026-05-02T10:44:00Z", "Enabled": true },
  { "Name": "WKS-0193",      "OperatingSystem": "Windows 11 Enterprise",          "LastLogonDate": "2026-06-18T07:30:12Z", "Enabled": true },
  { "Name": "WKS-0207",      "OperatingSystem": "Windows 10 Enterprise",          "LastLogonDate": null,                   "Enabled": true },
  { "Name": "WKS-0011",      "OperatingSystem": "Windows 10 Enterprise",          "LastLogonDate": "2025-12-01T09:00:00Z", "Enabled": false }
]
```

Audit date 2026-11-11; 90-day cut-off 2026-08-13. Stale and enabled:
`CONTOSO-FS02` (193 days), `WKS-0193` (146 days), `WKS-0207` (never logged
on). `WKS-0011` is already disabled.

Now each HR-supplied user:

```json
{ "name": "query-ad-user", "arguments": { "SamAccountName": "jlee" } }
```
```json
{ "SamAccountName": "jlee", "DisplayName": "Jordan Lee", "Enabled": true, "LastLogonDate": "2026-06-30T16:12:09Z", "Department": "Finance", "Title": "Senior Analyst" }
```

```json
{ "name": "query-ad-user", "arguments": { "SamAccountName": "mgarcia" } }
```
```json
{ "SamAccountName": "mgarcia", "DisplayName": "Morgan Garcia", "Enabled": false, "LastLogonDate": "2026-07-15T11:03:44Z", "Department": "Sales", "Title": "Account Executive" }
```

```json
{ "name": "query-ad-user", "arguments": { "SamAccountName": "tkowalski" } }
```
```json
{ "SamAccountName": "tkowalski", "DisplayName": "Taylor Kowalski", "Enabled": true, "LastLogonDate": "2026-07-29T09:41:27Z", "Department": "IT Operations", "Title": "Systems Administrator" }
```

```json
{ "name": "query-ad-user", "arguments": { "SamAccountName": "svc_legacyftp" } }
```
```json
{ "SamAccountName": "svc_legacyftp", "DisplayName": "Legacy FTP Service", "Enabled": true, "LastLogonDate": null, "Department": null, "Title": null }
```

```json
{ "name": "query-ad-user", "arguments": { "SamAccountName": "rpatel" } }
```
```text
Tool call rejected: jea-execution-error
```

The broker does not return the JEA error text, so this result alone cannot
tell "no such account" from an endpoint fault. The four `query-ad-user` calls
before it succeeded on the same endpoint, so the likely cause is that `rpatel`
no longer exists. I am recording it as Info, not verifiable via broker —
please confirm with `Get-ADUser -Identity rpatel`.

```json
{ "name": "list-ad-groups", "arguments": {} }
```
```json
[
  { "Name": "Domain Admins",    "GroupCategory": "Security",     "GroupScope": "Global" },
  { "Name": "Srv-Tier1-Admins", "GroupCategory": "Security",     "GroupScope": "Global" },
  { "Name": "Finance-ReadOnly", "GroupCategory": "Security",     "GroupScope": "Global" },
  { "Name": "Backup Operators", "GroupCategory": "Security",     "GroupScope": "DomainLocal" },
  { "Name": "DnsAdmins",        "GroupCategory": "Security",     "GroupScope": "DomainLocal" },
  { "Name": "All-Staff",        "GroupCategory": "Distribution", "GroupScope": "Universal" }
]
```

The broker cannot read AD group membership, so I will check where these
identities hold power locally on CONTOSO-APP01.

**SOP 3 — local privilege inspection**

```json
{ "name": "list-local-group-members", "arguments": { "GroupName": "Administrators" } }
```
```json
[
  { "Name": "CONTOSO-APP01\\Administrator", "ObjectClass": "User",  "PrincipalSource": "Local" },
  { "Name": "CONTOSO\\Domain Admins",       "ObjectClass": "Group", "PrincipalSource": "ActiveDirectory" },
  { "Name": "CONTOSO\\Srv-Tier1-Admins",    "ObjectClass": "Group", "PrincipalSource": "ActiveDirectory" },
  { "Name": "CONTOSO\\tkowalski",           "ObjectClass": "User",  "PrincipalSource": "ActiveDirectory" },
  { "Name": "CONTOSO-APP01\\helpdesk2",     "ObjectClass": "User",  "PrincipalSource": "Local" }
]
```

```json
{ "name": "list-local-group-members", "arguments": { "GroupName": "Remote Desktop Users" } }
```
```json
[
  { "Name": "CONTOSO\\jlee", "ObjectClass": "User", "PrincipalSource": "ActiveDirectory" }
]
```

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

```json
{ "name": "list-user-rights-assignments", "arguments": {} }
```
```json
[
  { "Privilege": "SeDebugPrivilege",              "AssignedTo": "*S-1-5-32-544" },
  { "Privilege": "SeImpersonatePrivilege",        "AssignedTo": "*S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6,*S-1-5-32-568,helpdesk2" },
  { "Privilege": "SeBackupPrivilege",             "AssignedTo": "*S-1-5-32-544,*S-1-5-32-551" },
  { "Privilege": "SeRemoteInteractiveLogonRight", "AssignedTo": "*S-1-5-32-544,*S-1-5-32-555" },
  { "Privilege": "SeDenyNetworkLogonRight",       "AssignedTo": "*S-1-5-32-546" }
]
```

`helpdesk2` is a local account in BUILTIN\Administrators, holds
`SeImpersonatePrivilege` explicitly, has a non-expiring password, and last
logged on at 02:13 UTC on a Sunday. That combination is Critical and a
possible compromise indicator. Checking for attached persistence.

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

`OneDriveSyncHealthCheck` scores 3 on the persistence rubric (root path,
non-admin author, name mimics a Microsoft component): MALICIOUS-LIKELY.

**SOP 4 — services and web**

```json
{ "name": "list-windows-services", "arguments": {} }
```
```json
[
  { "Name": "W3SVC",          "DisplayName": "World Wide Web Publishing Service",    "Status": "Stopped", "StartType": "Automatic" },
  { "Name": "WAS",            "DisplayName": "Windows Process Activation Service",   "Status": "Running", "StartType": "Manual" },
  { "Name": "Spooler",        "DisplayName": "Print Spooler",                        "Status": "Running", "StartType": "Automatic" },
  { "Name": "RemoteRegistry", "DisplayName": "Remote Registry",                      "Status": "Stopped", "StartType": "Disabled" },
  { "Name": "WinDefend",      "DisplayName": "Microsoft Defender Antivirus Service", "Status": "Running", "StartType": "Automatic" },
  { "Name": "MpsSvc",         "DisplayName": "Windows Defender Firewall",            "Status": "Running", "StartType": "Automatic" },
  { "Name": "EventLog",       "DisplayName": "Windows Event Log",                    "Status": "Running", "StartType": "Automatic" }
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
{ "name": "list-printers", "arguments": {} }
```
```json
[]
```

```json
{ "name": "list-firewall-rules", "arguments": {} }
```
```json
[
  { "Name": "IIS-WebServerRole-HTTPS-In-TCP", "DisplayName": "World Wide Web Services (HTTPS Traffic-In)", "Direction": "Inbound", "Action": "Allow", "Profile": "Domain" },
  { "Name": "WINRM-HTTP-In-TCP",              "DisplayName": "Windows Remote Management (HTTP-In)",        "Direction": "Inbound", "Action": "Allow", "Profile": "Domain" },
  { "Name": "RemoteDesktop-UserMode-In-TCP",  "DisplayName": "Remote Desktop - User Mode (TCP-In)",        "Direction": "Inbound", "Action": "Allow", "Profile": "Any" }
]
```

**Audit and attack-surface controls**

```json
{ "name": "get-audit-policy", "arguments": {} }
```
```json
[
  { "Subcategory": "Credential Validation",      "AuditCondition": "No Auditing" },
  { "Subcategory": "Logon",                      "AuditCondition": "Success and Failure" },
  { "Subcategory": "Special Logon",              "AuditCondition": "Success" },
  { "Subcategory": "Process Creation",           "AuditCondition": "No Auditing" },
  { "Subcategory": "Security Group Management",  "AuditCondition": "Success" },
  { "Subcategory": "User Account Management",    "AuditCondition": "Success" },
  { "Subcategory": "Other Object Access Events", "AuditCondition": "No Auditing" },
  { "Subcategory": "Audit Policy Change",        "AuditCondition": "Success" },
  { "Subcategory": "Security System Extension",  "AuditCondition": "Success" }
]
```

```json
{ "name": "get-applocker-policy", "arguments": {} }
```
```json
[
  { "CollectionType": "Exe",    "EnforcementMode": "AuditOnly",     "RuleCount": 3 },
  { "CollectionType": "Script", "EnforcementMode": "NotConfigured", "RuleCount": 0 }
]
```

```json
{ "name": "get-psremoting-status", "arguments": {} }
```
```json
{ "ServiceStatus": "Running", "StartType": "Automatic", "Listeners": [ { "Transport": "HTTP", "Address": "*", "Port": "5985", "Enabled": "true" } ] }
```

```json
{ "name": "list-bitlocker-volumes", "arguments": {} }
```
```json
[
  { "MountPoint": "C:", "VolumeStatus": "FullyEncrypted", "ProtectionStatus": "On",  "EncryptionPercentage": 100 },
  { "MountPoint": "D:", "VolumeStatus": "FullyDecrypted", "ProtectionStatus": "Off", "EncryptionPercentage": 0 }
]
```

Evidence collection complete. The report follows.

---

# AD & Server Hygiene Audit — contoso.com / CONTOSO-APP01

**Date:** 2026-11-11 · **Scope:** domain `contoso.com` (policy, PSOs, computer
objects, 5 named users); member server `CONTOSO-APP01` · **Mode:** read-only

## 1. Executive Summary

The audit found **4 Critical, 7 High, 5 Medium, and 5 Info** findings. The most
urgent issue is a probable host compromise on CONTOSO-APP01: a local account
`helpdesk2` with administrator rights and an explicit `SeImpersonatePrivilege`
grant authored a scheduled task in the root task folder disguised as a OneDrive
component. At domain level, account lockout is disabled
(`LockoutThreshold: 0`), leaving every account outside a PSO exposed to
unlimited password spraying, and Credential Validation auditing is off, so a
spray would go unrecorded on this host. A departed systems administrator
(`tkowalski`) is still enabled with direct local admin rights. Recommended
first actions: contain `helpdesk2` and its task, then disable the dormant
accounts. Both are staged below for approval.

## 2. Scope & Evidence

| Item | Value |
|---|---|
| Tools called | `get-domain-password-policy`, `list-fine-grained-password-policies`, `get-local-security-policy`, `list-ad-computers`, `query-ad-user` ×5, `list-ad-groups`, `list-local-group-members` ×2, `list-local-users`, `list-user-rights-assignments`, `list-scheduled-tasks`, `list-windows-services`, `list-iis-sites`, `list-printers`, `list-firewall-rules`, `get-audit-policy`, `get-applocker-policy`, `get-psremoting-status`, `list-bitlocker-volumes` |
| Write-tier calls | None |
| Capability gaps | No bulk AD user enumeration; no AD group membership read; no event log read; PSO `MaxPasswordAge` / `AppliesTo` not exposed |

## 3. Findings

| ID | Severity | Area | Finding | Evidence | CIS ref | Recommendation |
|---|---|---|---|---|---|---|
| F-01 | **Critical** | Privilege / IOC | Local account `helpdesk2` is in BUILTIN\Administrators | `list-local-group-members` Administrators → `CONTOSO-APP01\helpdesk2`, `PrincipalSource: Local` | Local admin hygiene | Disable account (R-01) |
| F-02 | **Critical** | Privilege / IOC | `helpdesk2` explicitly holds `SeImpersonatePrivilege` | `list-user-rights-assignments` → `SeImpersonatePrivilege … helpdesk2` | 2.2.32 | Disable (R-01); remove grant via GPO (O-04) |
| F-03 | **Critical** | Persistence / IOC | Task `\OneDriveSyncHealthCheck` authored by `helpdesk2`, root folder, Microsoft-mimicking name | `list-scheduled-tasks` → `TaskPath: "\"`, `Author: CONTOSO-APP01\helpdesk2` | 18 (persistence surface) | Disable task (R-02); preserve XML |
| F-04 | **Critical** | Lockout | Domain account lockout disabled | `get-domain-password-policy` → `LockoutThreshold: 0` | 1.2.2 | Threshold 5, duration / window 15 min (O-01) |
| F-05 | **High** | Identity | Departed sysadmin `tkowalski` enabled, 105 days inactive, **direct** local admin on APP01 | `query-ad-user` → `Enabled: true`, `LastLogonDate: 2026-07-29`; Administrators → `CONTOSO\tkowalski` | 18 (identity hygiene) | Disable (R-03); remove local membership (O-05) |
| F-06 | **High** | Identity | Departed `jlee` enabled, 134 days inactive, in Remote Desktop Users | `query-ad-user` → `Enabled: true`, `LastLogonDate: 2026-06-30` | 18 (identity hygiene) | Disable (R-04) |
| F-07 | **High** | Identity | `svc_legacyftp` enabled, never logged on, on HR leaver list | `query-ad-user` → `LastLogonDate: null` | 18 (identity hygiene) | Owner sign-off, then disable (R-05) |
| F-08 | **High** | Password | Minimum length 8; maximum age 180 days | `MinPasswordLength: 8`, `MaxPasswordAge: 180.00:00:00` | 1.1.4, 1.1.2 | Raise to 14 / 90 days (O-01) |
| F-09 | **High** | FGPP | Admin PSO loses to user PSO on precedence | `PSO-StandardUsers` 10 < `PSO-Tier0-Admins` 20 | 1.1 (FGPP) | Set `PSO-Tier0-Admins` precedence 1 (O-02) |
| F-10 | **High** | FGPP | Service-account PSO disables lockout | `PSO-ServiceAccounts` → `LockoutThreshold: 0` | 1.2.2 | Threshold ≤ 10, or gMSA migration (O-02) |
| F-11 | **High** | Audit | Credential Validation not audited — NTLM spraying (4776) invisible | `get-audit-policy` → `Credential Validation: No Auditing` | 17.1.1 | Success and Failure (O-03) |
| F-12 | **Medium** | Services | Print Spooler running on a non-print server | `Spooler: Running / Automatic`; `list-printers` → `[]` | 5.2 | Stop (R-06); Disabled via GPO (O-06) |
| F-13 | **Medium** | Stale objects | 3 enabled computer objects inactive > 90 days | `CONTOSO-FS02` 2026-05-02, `WKS-0193` 2026-06-18, `WKS-0207` null | 18 (stale objects) | Disable after CMDB check (R-07 – R-09) |
| F-14 | **Medium** | FGPP | PSO precedence tie at 20 | `PSO-Tier0-Admins`, `PSO-ServiceAccounts` | 1.1 (FGPP) | Unique precedence (O-02) |
| F-15 | **Medium** | ASR | AppLocker Exe `AuditOnly`, Script not configured; Process Creation not audited | `get-applocker-policy`; `get-audit-policy` | 18 / 17.3.2 | Plan enforcement; enable 4688 (O-03) |
| F-16 | **Medium** | Remote mgmt / data | WinRM HTTP-only listener; D: (site content) not BitLocker-protected | `get-psremoting-status` → `Transport: HTTP`; `list-bitlocker-volumes` → `D: ProtectionStatus: Off` | 18 | HTTPS listener; encrypt D: (O-07) |
| F-17 | **Info** | Availability | W3SVC stopped (Automatic); `Contoso-Intranet` stopped | `W3SVC: Stopped`; `list-iis-sites` → `State: Stopped` | — | Investigate before restart — may relate to F-01 – F-03 |
| F-18 | **Info** | Identity | `mgarcia` already disabled | `Enabled: false` | — | Deletion review after retention |
| F-19 | **Info** | Identity | `rpatel` could not be read — probably already deprovisioned | `query-ad-user` → `jea-execution-error` (no detail returned); four sibling lookups succeeded | — | Operator confirms with `Get-ADUser -Identity rpatel` |
| F-20 | **Info** | Policy | Local SAM password / lockout policy compliant on APP01 | `get-local-security-policy` | 1.1 / 1.2 | None |
| F-21 | **Info** | Built-ins | Built-in Administrator and Guest disabled; `SeDebugPrivilege` correctly scoped | `list-local-users`; `list-user-rights-assignments` | 2.3.1 / 2.2.21 | None |

## 4. Remediation Plan

### 4.1 Broker-executable (each requires an approval card)

Dispatch in this order. Verify each before the next.

| Ref | Fixes | Tool call | Verify with | Rollback |
|---|---|---|---|---|
| R-01 | F-01, F-02 | `set-local-user-enabled {UserName: "helpdesk2", Enabled: "false"}` | `list-local-users` | `Enabled: "true"` |
| R-02 | F-03 | `set-scheduled-task-state {TaskPath: "\\", TaskName: "OneDriveSyncHealthCheck", Enabled: "false"}` | `list-scheduled-tasks` | `Enabled: "true"` |
| R-03 | F-05 | `set-ad-user-enabled {SamAccountName: "tkowalski", Enabled: "false"}` | `query-ad-user` | `Enabled: "true"` |
| R-04 | F-06 | `set-ad-user-enabled {SamAccountName: "jlee", Enabled: "false"}` | `query-ad-user` | `Enabled: "true"` |
| R-05 | F-07 | `set-ad-user-enabled {SamAccountName: "svc_legacyftp", Enabled: "false"}` — **after owner sign-off** | `query-ad-user` | `Enabled: "true"` |
| R-06 | F-12 | `set-windows-service-state {ServiceName: "Spooler", Action: "Stop"}` | `list-windows-services` | `Action: "Start"` |
| R-07 | F-13 | `set-ad-computer-enabled {ComputerName: "CONTOSO-FS02", Enabled: "false"}` | `list-ad-computers` | `Enabled: "true"` |
| R-08 | F-13 | `set-ad-computer-enabled {ComputerName: "WKS-0193", Enabled: "false"}` | `list-ad-computers` | `Enabled: "true"` |
| R-09 | F-13 | `set-ad-computer-enabled {ComputerName: "WKS-0207", Enabled: "false"}` | `list-ad-computers` | `Enabled: "true"` |

R-01 and R-02 contain a suspected compromise and should be approved first.
Restarting W3SVC (F-17) is deliberately **not** proposed until the operator
confirms the outage is unrelated to the attacker.

### 4.2 Operator action — not executable via broker

| Ref | Fixes | Action |
|---|---|---|
| O-01 | F-04, F-08 | `Set-ADDefaultDomainPasswordPolicy -Identity contoso.com -LockoutThreshold 5 -LockoutDuration 00:15:00 -LockoutObservationWindow 00:15:00 -MinPasswordLength 14 -MaxPasswordAge 90.00:00:00` |
| O-02 | F-09, F-10, F-14 | `Set-ADFineGrainedPasswordPolicy -Identity PSO-Tier0-Admins -Precedence 1`; `Set-ADFineGrainedPasswordPolicy -Identity PSO-ServiceAccounts -Precedence 30 -LockoutThreshold 10` |
| O-03 | F-11, F-15 | GPO Advanced Audit Policy: Account Logon\Credential Validation = Success and Failure; Detailed Tracking\Process Creation = Success; Object Access\Other Object Access Events = Success and Failure |
| O-04 | F-02 | GPO User Rights Assignment: remove `helpdesk2` from *Impersonate a client after authentication* |
| O-05 | F-05 | Remove `CONTOSO\tkowalski` from local Administrators via GPO Restricted Groups; grant admin only through `Srv-Tier1-Admins` |
| O-06 | F-12 | GPO System Services: Print Spooler = Disabled |
| O-07 | F-16 | Configure WinRM HTTPS listener with enterprise certificate; `Enable-BitLocker -MountPoint D: -RecoveryPasswordProtector` |
| O-08 | F-01 – F-03 | Incident response: preserve task XML and the `helpdesk2` profile; pull 4624 / 4672 for `helpdesk2` from SIEM; rotate LAPS password; hunt `OneDriveSyncHealthCheck` fleet-wide (see `references/incident-triage.md`, Playbook D) |

## 5. Not Verified

- Domain group memberships of `jlee`, `tkowalski`, `svc_legacyftp` (no broker tool).
- Directory-wide dormant-user population beyond the 5 supplied names.
- Whether `rpatel` still exists: `query-ad-user` returned `jea-execution-error`
  and the broker passes no error detail to the caller (F-19).
- PSO `MaxPasswordAge` and `AppliesTo` targeting.
- Event-log evidence of `helpdesk2` activity (no event-log tool).
- CIS 2.3 Security Options (LDAP / SMB signing, NTLM restrictions).

---

### Turn 2 — Operator

> Good. Start with R-01 and R-02.

### Turn 2 — Agent

Proceeding with containment, one approval card at a time. The full
approval-gated write loop for this step is shown in
`examples/remediation-flow.md`.

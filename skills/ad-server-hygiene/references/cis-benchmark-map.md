# CIS Windows Server 2022/2025 Benchmark → Windows-Server-MCP Tool Map

This map links the major CIS Microsoft Windows Server 2022 / 2025 Benchmark
sections to the broker tools (`toolId` from `policy/manifest.json`) that can
**observe** or **remediate** each control.

Column legend:

- **Observe** — read-tier tool and output field that evidences the control.
- **Remediate** — write-tier tool (approval card required), or `Operator` when
  the broker has no write path.
- **Coverage** — `Full` (observable and broker-remediable), `Observe` (read
  only; remediation is an operator change request), `Partial` (only some
  aspects observable or remediable), `None` (outside broker scope; report as
  "Not verified").

Recommendation numbers follow the CIS Server 2022/2025 layout. Numbering can
shift slightly between benchmark releases, so always cite the control
**title** alongside the number.

---

## 1. Account Policies

### 1.1 Password Policy

| CIS ref | Control | Target (L1) | Observe | Remediate | Coverage |
|---|---|---|---|---|---|
| 1.1.1 | Enforce password history | ≥ 24 | `get-domain-password-policy` → `PasswordHistoryCount`; `get-local-security-policy` → `PasswordHistorySize` | Operator | Observe |
| 1.1.2 | Maximum password age | 1–365 days (house rule ≤ 90) | `get-domain-password-policy` → `MaxPasswordAge`; `get-local-security-policy` → `MaximumPasswordAge` | Operator | Observe |
| 1.1.3 | Minimum password age | ≥ 1 day | `get-domain-password-policy` → `MinPasswordAge`; `get-local-security-policy` → `MinimumPasswordAge` | Operator | Observe |
| 1.1.4 | Minimum password length | ≥ 14 | `get-domain-password-policy` → `MinPasswordLength`; `list-fine-grained-password-policies` → `MinPasswordLength`; `get-local-security-policy` → `MinimumPasswordLength` | Operator | Observe |
| 1.1.5 | Password must meet complexity requirements | Enabled | `get-domain-password-policy` → `ComplexityEnabled`; `list-fine-grained-password-policies` → `ComplexityEnabled`; `get-local-security-policy` → `PasswordComplexity` | Operator | Observe |
| 1.1.6 | Relax minimum password length limits | Enabled | — | Operator | None |
| 1.1.7 | Store passwords using reversible encryption | Disabled | `get-domain-password-policy` → `ReversibleEncryptionEnabled` | Operator | Observe |
| — | Fine-grained PSO precedence and admin-tier strictness | Admin PSO strictest, unique precedence | `list-fine-grained-password-policies` → `Precedence`, `LockoutThreshold`, `MinPasswordLength`, `ComplexityEnabled` | Operator | Partial (no `MaxPasswordAge` / `AppliesTo`) |

### 1.2 Account Lockout Policy

| CIS ref | Control | Target (L1) | Observe | Remediate | Coverage |
|---|---|---|---|---|---|
| 1.2.1 | Account lockout duration | ≥ 15 minutes | `get-domain-password-policy` → `LockoutDuration`; `get-local-security-policy` → `LockoutDuration` | Operator | Observe |
| 1.2.2 | Account lockout threshold | 1–5 (house rule 1–10; `0` = Critical) | `get-domain-password-policy` → `LockoutThreshold`; `list-fine-grained-password-policies` → `LockoutThreshold`; `get-local-security-policy` → `LockoutBadCount` | Operator | Observe |
| 1.2.3 | Allow Administrator account lockout | Enabled (Member Server) | — | Operator | None |
| 1.2.4 | Reset account lockout counter after | ≥ 15 minutes | `get-domain-password-policy` → `LockoutObservationWindow`; `get-local-security-policy` → `ResetLockoutCount` | Operator | Observe |

---

## 2. Local Policies

### 2.2 User Rights Assignment

For every row: **Observe** = `list-user-rights-assignments` → `Privilege` /
`AssignedTo`. **Remediate** = Operator (GPO), unless the excess holder is an
account that should be disabled outright (`set-local-user-enabled` /
`set-ad-user-enabled`).

| CIS ref | Control | Privilege constant | Target holders (MS = Member Server, DC = Domain Controller) | Coverage |
|---|---|---|---|---|
| 2.2.1 | Access Credential Manager as a trusted caller | `SeTrustedCredManAccessPrivilege` | No One | Observe |
| 2.2.3 / 2.2.4 | Access this computer from the network | `SeNetworkLogonRight` | Administrators, Authenticated Users (+ ENTERPRISE DOMAIN CONTROLLERS on DC) | Observe |
| 2.2.5 | Act as part of the operating system | `SeTcbPrivilege` | No One | Observe |
| 2.2.7 | Adjust memory quotas for a process | `SeIncreaseQuotaPrivilege` | Administrators, LOCAL SERVICE, NETWORK SERVICE | Observe |
| 2.2.8 / 2.2.9 | Allow log on locally | `SeInteractiveLogonRight` | Administrators (+ ENTERPRISE DOMAIN CONTROLLERS on DC) | Observe |
| 2.2.10 / 2.2.11 | Allow log on through Remote Desktop Services | `SeRemoteInteractiveLogonRight` | MS: Administrators, Remote Desktop Users. DC: Administrators | Observe |
| 2.2.12 | Back up files and directories | `SeBackupPrivilege` | Administrators | Observe |
| 2.2.16 | Create a token object | `SeCreateTokenPrivilege` | No One | Observe |
| 2.2.17 | Create global objects | `SeCreateGlobalPrivilege` | Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE | Observe |
| 2.2.18 | Create permanent shared objects | `SeCreatePermanentPrivilege` | No One | Observe |
| 2.2.21 | Debug programs | `SeDebugPrivilege` | Administrators | Observe |
| 2.2.22 / 2.2.23 | Deny access to this computer from the network | `SeDenyNetworkLogonRight` | Guests; MS: + Local account and member of Administrators group | Observe |
| 2.2.26 / 2.2.27 | Deny log on through Remote Desktop Services | `SeDenyRemoteInteractiveLogonRight` | Guests; MS: + Local account | Observe |
| 2.2.28 / 2.2.29 | Enable accounts to be trusted for delegation | `SeEnableDelegationPrivilege` | DC: Administrators. MS: No One | Observe |
| 2.2.31 | Generate security audits | `SeAuditPrivilege` | LOCAL SERVICE, NETWORK SERVICE | Observe |
| 2.2.32 / 2.2.33 | Impersonate a client after authentication | `SeImpersonatePrivilege` | Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE (+ IIS_IUSRS where IIS installed) | Observe |
| 2.2.35 | Load and unload device drivers | `SeLoadDriverPrivilege` | Administrators | Observe |
| 2.2.36 | Lock pages in memory | `SeLockMemoryPrivilege` | No One | Observe |
| 2.2.39 / 2.2.40 | Manage auditing and security log | `SeSecurityPrivilege` | Administrators | Observe |
| 2.2.41 | Modify an object label | `SeRelabelPrivilege` | No One | Observe |
| 2.2.44 | Replace a process level token | `SeAssignPrimaryTokenPrivilege` | LOCAL SERVICE, NETWORK SERVICE | Observe |
| 2.2.45 | Restore files and directories | `SeRestorePrivilege` | Administrators | Observe |
| 2.2.48 | Take ownership of files or other objects | `SeTakeOwnershipPrivilege` | Administrators | Observe |

Well-known SIDs as they appear in `AssignedTo`:

| SID | Principal |
|---|---|
| `*S-1-5-32-544` | BUILTIN\Administrators |
| `*S-1-5-32-545` | BUILTIN\Users |
| `*S-1-5-32-546` | BUILTIN\Guests |
| `*S-1-5-32-551` | BUILTIN\Backup Operators |
| `*S-1-5-32-555` | BUILTIN\Remote Desktop Users |
| `*S-1-5-32-568` | IIS_IUSRS |
| `*S-1-5-19` | LOCAL SERVICE |
| `*S-1-5-20` | NETWORK SERVICE |
| `*S-1-5-6` | SERVICE |
| `*S-1-5-11` | Authenticated Users |
| `*S-1-5-9` | ENTERPRISE DOMAIN CONTROLLERS |
| `*S-1-5-113` | Local account |
| `*S-1-5-114` | Local account and member of Administrators group |

### 2.3 Security Options

| CIS ref | Control | Observe | Remediate | Coverage |
|---|---|---|---|---|
| 2.3.1.x | Accounts: Guest account status = Disabled | `list-local-users` → `Name: Guest`, `Enabled` | `set-local-user-enabled` refuses built-ins — Operator | Observe |
| 2.3.1.x | Accounts: Rename administrator / guest account | `list-local-users` → `Name` | Operator | Observe |
| 2.3.x | Network security: LDAP signing, SMB signing, NTLM restrictions, LAN Manager level | — | Operator | None |

### Local group membership (supports 2.2 and 2.3)

| Control intent | Observe | Remediate | Coverage |
|---|---|---|---|
| BUILTIN\Administrators contains only approved principals | `list-local-group-members {GroupName: "Administrators"}` | Disable rogue principal with `set-local-user-enabled` / `set-ad-user-enabled`; membership edit = Operator | Partial |
| Backup Operators empty on member servers | `list-local-group-members {GroupName: "Backup Operators"}` | Same as above | Partial |
| Remote Desktop Users restricted | `list-local-group-members {GroupName: "Remote Desktop Users"}` | Same as above | Partial |
| Guests contains no enabled accounts | `list-local-group-members {GroupName: "Guests"}` + `list-local-users` | `set-local-user-enabled` (non-built-in accounts only) | Partial |
| Domain privileged-group hygiene | `list-ad-groups` (inventory only) | `set-ad-group-membership {Action: "Remove"}` on **non-protected** groups only | Partial |

---

## 5. System Services

| CIS ref | Service (`Name`) | Target | Observe | Remediate | Coverage |
|---|---|---|---|---|---|
| 5.1 | Print Spooler (`Spooler`) on DC | Disabled | `list-windows-services` → `Status`, `StartType`; `list-printers` | `set-windows-service-state {ServiceName: "Spooler", Action: "Stop"}`; start type = Operator | Partial |
| 5.2 | Print Spooler (`Spooler`) on non-print MS | Disabled | same | same | Partial |
| L2 | Remote Registry (`RemoteRegistry`) | Disabled | `list-windows-services` | `set-windows-service-state {ServiceName: "RemoteRegistry", Action: "Stop"}` | Partial |
| L2 | SNMP Service (`SNMP`) | Not installed / Disabled | `list-windows-services`, `list-windows-features` | `set-windows-service-state {ServiceName: "SNMP", Action: "Stop"}` | Partial |
| — | Microsoft FTP Service (`FTPSVC`) | Not installed unless required | `list-ftp-sites`, `list-windows-features` | `set-windows-service-state {ServiceName: "FTPSVC", Action: "Stop"}` | Partial |
| — | Windows Remote Management (`WinRM`) | Running, HTTPS listener only | `get-psremoting-status` → `Listeners[].Transport` | Denied by wrapper — Operator | Observe |
| — | Windows Defender Firewall (`MpsSvc`) | Running / Automatic | `list-windows-services` | Denied by wrapper (protects host) | Observe |
| — | Microsoft Defender (`WinDefend`, `Sense`) | Running | `list-windows-services` | Denied by wrapper | Observe |

`set-windows-service-state` changes run state only. An `Automatic` service
returns after reboot, so always pair a Stop with an operator change request to
set start type to Disabled via GPO (`Computer Configuration\Policies\Windows
Settings\Security Settings\System Services`).

---

## 9. Windows Defender Firewall with Advanced Security

| CIS ref | Control | Observe | Remediate | Coverage |
|---|---|---|---|---|
| 9.1–9.3 | Firewall state On for Domain / Private / Public profiles | `list-windows-services` → `MpsSvc` Running; `list-firewall-rules` → `Profile` | Operator | Partial |
| 9.x | Inbound default Block; only documented allow rules | `list-firewall-rules` → `Direction: Inbound`, `Action: Allow` | `set-firewall-rule-enabled {RuleName, Enabled: "false"}` for an undocumented allow rule | Partial |
| — | Pre-staged incident block rules available | Operator runbook (disabled rules are not listed by the broker) | `set-firewall-rule-enabled {RuleName, Enabled: "true"}` | Partial |

---

## 17. Advanced Audit Policy Configuration

**Observe** = `get-audit-policy` → `Subcategory` / `AuditCondition`
(`Success`, `Failure`, `Success and Failure`, `No Auditing`).
**Remediate** = Operator (GPO `Advanced Audit Policy Configuration`).

| CIS ref | Subcategory | Target | Why this skill cares |
|---|---|---|---|
| 17.1.1 | Credential Validation | Success and Failure | Generates **4776** (NTLM spraying) |
| 17.1.2 | Kerberos Authentication Service (DC) | Success and Failure | Generates **4768 / 4771** (Kerberos spraying) |
| 17.1.3 | Kerberos Service Ticket Operations (DC) | Success and Failure | Generates **4769** (Kerberoasting) |
| 17.2.1 | Application Group Management | Success and Failure | Group tampering |
| 17.2.5 | Security Group Management | Success | Generates **4728 / 4732 / 4756** |
| 17.2.6 | User Account Management | Success and Failure | Generates **4720 / 4722 / 4725** |
| 17.3.1 | Plug and Play Events | Success | BYOVD / removable devices |
| 17.3.2 | Process Creation | Success | Generates **4688** |
| 17.5.1 | Account Lockout | Failure | Generates **4625** lockout context |
| 17.5.4 | Logon | Success and Failure | Generates **4624 / 4625** (including Logon Type 9) |
| 17.5.5 | Other Logon/Logoff Events | Success and Failure | RDP reconnect / session events |
| 17.5.6 | Special Logon | Success | Generates **4672** (privileged logon) |
| 17.6.3 | Other Object Access Events | Success and Failure | Generates **4698** (scheduled task created) |
| 17.7.1 | Audit Policy Change | Success | Tamper detection |
| 17.7.3 | Authorization Policy Change | Success | User-rights tampering |
| 17.8.1 | Sensitive Privilege Use | Success and Failure | `SeDebugPrivilege` use |
| 17.9.3 | Security State Change | Success | — |
| 17.9.4 | Security System Extension | Success | Generates **4697** (service installed) |
| 17.9.5 | System Integrity | Success and Failure | — |

**7045** (new service installed) is written to the System log by the Service
Control Manager regardless of audit policy. The broker cannot read event logs;
confirm visibility through the SIEM.

---

## 18. Administrative Templates & Attack Surface Reduction

| Area | Control intent | Observe | Remediate | Coverage |
|---|---|---|---|---|
| Application control | AppLocker / WDAC enforced for Exe, Script, Dll, Msi | `get-applocker-policy` → `CollectionType`, `EnforcementMode`, `RuleCount` | Operator | Observe |
| PowerShell | Execution policy `AllSigned` / `RemoteSigned` at `MachinePolicy` | `get-execution-policy` → `Scope`, `ExecutionPolicy` | Operator | Observe |
| Remote management | WinRM HTTPS only; JEA endpoints registered and scoped | `get-psremoting-status`; `list-jea-endpoints` | Operator | Observe |
| Data at rest | BitLocker on OS and data volumes | `list-bitlocker-volumes` → `ProtectionStatus`, `VolumeStatus` | Operator | Observe |
| SMB exposure | No unnecessary shares | `list-smb-shares` → `Name`, `Path`, `ShareType` | Operator | Partial |
| Role minimisation | Only required roles / features installed | `list-windows-features {InstalledOnly: "true"}` | Operator | Observe |
| Web surface | No default or unused IIS / FTP sites | `list-iis-sites`, `list-ftp-sites` | `set-iis-site-state {SiteName, Action: "Stop"}` | Partial |
| Persistence surface | No scheduled tasks from unknown authors outside `\Microsoft\` | `list-scheduled-tasks` → `TaskPath`, `Author`, `State` | `set-scheduled-task-state {TaskPath, TaskName, Enabled: "false"}` | Full |
| GPO hygiene | No orphaned / unexpectedly modified GPOs | `list-group-policies` → `GpoStatus`, `ModificationTime` | `set-gpo-status` (never Default Domain / DC policy) | Full |
| Stale objects | Disable computer objects with `LastLogonDate` > 90 days | `list-ad-computers` → `LastLogonDate`, `Enabled` | `set-ad-computer-enabled {ComputerName, Enabled: "false"}` | Full |
| Identity hygiene | Disable dormant user accounts | `query-ad-user` → `Enabled`, `LastLogonDate` (per name) | `set-ad-user-enabled {SamAccountName, Enabled: "false"}` | Partial (no bulk enumeration) |
| Broker self-audit | JEA transcript volume per day within expected range | `summarize-transcript-logs {DaysBack: 7}` | — | Observe |

---

## Coverage Summary

| CIS section | Observable via broker | Broker-remediable |
|---|---|---|
| 1. Account Policies | Most settings | No — operator change request |
| 2.2 User Rights Assignment | All rights | No — disable the offending principal only |
| 2.3 Security Options | Guest / Administrator account state only | No |
| 5. System Services | Run state and start type | Run state only, non-critical services only |
| 9. Firewall | Enabled rules | Toggle existing rules |
| 17. Advanced Audit Policy | All subcategories | No |
| 18. Admin Templates / ASR | AppLocker, execution policy, BitLocker, roles, shares, tasks, GPOs | Tasks, IIS sites, GPO status, stale AD objects |

Any CIS control not listed above must be reported as **"Not verified —
outside broker scope"** in the audit report.

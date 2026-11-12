# Review Prompt — `skills/ad-server-hygiene` Agent Skill

Copy everything below the line into a fresh AI session (Claude Code, Codex,
Cursor agent, etc.) opened at the repository root.

---

## Role

You are an independent reviewer of an Agent Skill package for
**Windows-Server-MCP**, a zero-trust MCP broker for Windows Server 2022/2025.
You are a skeptic. Your job is to find every place where the skill is wrong,
unsafe, inconsistent, or incomplete. Do not praise. Do not assume a claim is
correct because it sounds plausible. Check every claim against the source of
truth in this repository.

Work **read-only** unless the final section tells you to fix. Never connect to
a real server, run broker tools, or execute any PowerShell from the skill.

## Files under review

```
skills/ad-server-hygiene/
├── SKILL.md
├── references/cis-benchmark-map.md
├── references/incident-triage.md
├── examples/audit-session.md
└── examples/remediation-flow.md
```

## Sources of truth (the skill must match these, not the other way round)

| Topic | File(s) |
|---|---|
| Tool IDs, risk tier, parameters, allowlists, masked fields, untrusted sources | `policy/manifest.json` (UTF-8 **with BOM** — load with `utf-8-sig`) |
| Tool output field names, wrapper deny lists | `jea/modules/*.psm1` (the `[pscustomobject]@{...}` blocks and `throw "... denied by policy ..."` lines) |
| Rejection reason strings | `src/Broker.Policy/Policy.cs`, `src/Broker.Host/BrokerPipeline.cs` |
| MCP result shape (`isError`, `Tool call rejected:`, `Execution error:`) | `src/Broker.McpAdapter/McpServer.cs` |
| Approval card text and approver CLI output | `src/Broker.ApproverCli/ApproverClient.cs`, `src/Broker.ApproverCli/Program.cs` |
| Approval pipe name, TTL, other config | `src/Broker.Host/appsettings.json`, `src/Broker.Transport/Transport.cs` |
| Architecture and intent | `README.md`, `docs/ai-autoconfiguration.md`, `docs/security-hardening.md` |

If a source of truth and the skill disagree, the skill is wrong. If two
sources of truth disagree with each other, report that as a separate finding.

## Original requirements the skill was built from

1. Exact paths above.
2. `SKILL.md` YAML frontmatter with exactly: `name: ad-server-hygiene`,
   `description`, `version: 1.0.0`, `author: Windows-Server-MCP Core Team`,
   `tags: [windows-server, active-directory, sysadmin, security, zero-trust, cis-compliance]`.
3. Activation triggers: AD health, dormant/zombie users, password policy
   audits; CIS posture and health checks; stopped core services (DNS, DHCP,
   IIS, Netlogon, Spooler); suspicious events 4624 Type 9, 4771/4776, 7045.
4. Four SOPs: (1) identity governance / zombie accounts with a 90-day dormancy
   rule; (2) password and lockout drift, including FGPP precedence, lockout
   threshold 1–10 (not 0), max password age ≤ 90 days; (3) local privilege
   escalation — `SeImpersonatePrivilege`, `SeDebugPrivilege`,
   BUILTIN\Administrators (S-1-5-32-544); (4) service self-healing.
5. Invariants: read-first; the approval reminder **verbatim**:
   `Action card dispatched to \\.\pipe\McpBroker.Approvals. Please review and authorize by pressing [y] in the Broker.ApproverCli terminal.`;
   never modify Default Domain Policy or Default Domain Controllers Policy;
   never add members to Domain Admins (RID -512) or `adminCount=1` groups.
6. `cis-benchmark-map.md`: table mapping CIS sections (Account Policies, User
   Rights, Audit Policies, System Services, Attack Surface Reduction) to tool IDs.
7. `incident-triage.md`: decision trees for password spraying →
   `set-firewall-rule-enabled`; web exploit → `set-iis-site-state`;
   persistent backdoor → `set-scheduled-task-state`.
8. `audit-session.md`: multi-turn transcript ending in an executive report with
   Critical / High / Medium / Info severities.
9. `remediation-flow.md`: multi-turn transcript of discover → propose →
   Broker.ApproverCli approval → verify.
10. All tool and parameter names must match `policy/manifest.json` (62 tools).
11. Production quality, no placeholders.

**Known, intentional deviations.** Confirm each one is actually true. Do not
flag them as defects just because they deviate from the requirements.

- There is no `list-ad-users` tool. The skill must say so and must never call it.
- `set-windows-service-state` uses `ServiceName` + `Action` (`Start`/`Stop`), not `Name` + `State`.
- `Dns`, `Dhcp`, and `Netlogon` are on the service wrapper deny list, so SOP 4
  must escalate rather than propose starting them.
- The broker has no event-log reader, cannot create firewall rules, cannot read
  AD group membership, and FGPP output lacks `MaxPasswordAge` and `AppliesTo`.

If any "known deviation" turns out to be untrue, that is a Critical finding.

## Review checklist

Work through every section. Record PASS or a finding for each item.

### A. Structure and frontmatter
- A1. All five files exist at the exact paths. No extra or misplaced files.
- A2. Frontmatter parses as YAML and matches requirement 2 exactly (field
  names, values, tag order).
- A3. No placeholders anywhere. Search for `TODO`, `TBD`, `XXX`, `lorem`,
  `<placeholder>`, `...` standing in for omitted content, and empty table cells
  that were meant to be filled. Tokens such as `<name>` inside decision-tree
  pseudo-code are acceptable only where they clearly mean "the value from the
  read result".

### B. Tool fidelity (highest priority)
- B1. Every token that looks like a tool ID (`list-*`, `get-*`, `set-*`,
  `query-*`, `summarize-*`) exists in `policy/manifest.json`. The only allowed
  exception is `list-ad-users` inside the sentence stating that it does not exist.
- B2. Every tool call, whether in JSON form (`{"name": ..., "arguments": {...}}`)
  or inline form (`tool {Param: value}`), uses only parameters declared for that
  tool, includes every `required: true` parameter, and uses values that pass the
  allowlist (`regexPattern`, `enumValues`, `range`, `maxLength`). Test the
  regexes against the actual example values, e.g. `TaskPath` `"\"` against
  `^(\\|\\[\\A-Za-z0-9 _.-]*\\)$`.
- B3. Booleans are passed as the strings `"true"` / `"false"` (the allowlists are
  `enumValues: ["true","false"]`).
- B4. The risk tier the skill states for each tool matches the manifest
  (`read` vs `write`). The counts "49 read / 13 write / 62 total" are correct.
- B5. Every **output field** shown in tables, prose, and example JSON results
  exists, with the same spelling, in the output object of the corresponding
  `jea/modules/Get-Broker*.psm1` / `Set-Broker*.psm1` module. Fields the
  manifest lists as masked (`objectSid`, `distinguishedName`, `SID`,
  `KeyProtectorId`, `RecoveryPassword`) must not appear unmasked in example output.
- B6. Allowlisted enum values quoted in the skill (e.g. the
  `list-local-group-members` `GroupName` values, the `set-gpo-status` `Status`
  values, `set-cluster-node-state` `Pause`/`Resume`) exactly match the manifest.

Recommended automated pass (adapt as needed):

```python
import json, re, glob
m = json.load(open('policy/manifest.json', encoding='utf-8-sig'))
tools = {t['toolId']: t for t in m['tools']}
for f in glob.glob('skills/ad-server-hygiene/**/*.md', recursive=True):
    s = open(f, encoding='utf-8').read()
    for tok in set(re.findall(r'`((?:list|get|set|query|summarize)-[a-z0-9-]+)`', s)):
        if tok not in tools: print(f, 'UNKNOWN TOOL', tok)
    for name, args in re.findall(r'"name":\s*"([a-z0-9-]+)",\s*"arguments":\s*(\{[^}]*\})', s):
        t = tools.get(name)
        if not t: print(f, 'UNKNOWN', name); continue
        a = json.loads(args)
        declared = {p['name']: p for p in t['parameters']}
        for k, v in a.items():
            p = declared.get(k)
            if not p: print(f, name, 'UNDECLARED PARAM', k); continue
            al = p.get('allowlist', {})
            if 'enumValues' in al and str(v) not in al['enumValues']: print(f, name, k, 'NOT IN ENUM', v)
            if 'regexPattern' in al and not re.fullmatch(al['regexPattern'], str(v)): print(f, name, k, 'REGEX FAIL', v)
        for k, p in declared.items():
            if p.get('required') and k not in a: print(f, name, 'MISSING REQUIRED', k)
```

This script does not catch inline `tool {Param: value}` calls or calls written
in prose. Check those by hand.

### C. Guard and protocol fidelity
- C1. Every wrapper deny list the skill quotes (services, AD users, local users,
  privileged groups, DC computers, Default Domain GPO names and GUIDs) matches
  the `.psm1` source exactly. Nothing missing, nothing invented.
- C2. Every rejection reason string in the skill (`elicitation-denied`,
  `elicitation-timeout-or-disconnect`, `distinct-approver-required`,
  `untrusted-source-cannot-mutate`, `rate-limit-exceeded`, …) exists in
  `Policy.cs` / `BrokerPipeline.cs`. Also report real reasons an agent is likely
  to hit that the skill omits.
- C3. The rejected-result text format in the examples (`Tool call rejected: <reason>`,
  `Execution error: <message>`) matches `McpServer.cs`.
- C4. The approval cards in `remediation-flow.md` match the exact layout printed
  by `ApproverClient.cs`: header lines, field labels and padding, the `[y/N]`
  prompt, and the `Decision submitted:` line.
- C5. The pipe name `McpBroker.Approvals` and the 120-second TTL match config.
  The claims "the approver must differ from the caller" and "the approver must
  be in the approver group" are backed by code.
- C6. The verbatim approval reminder from requirement 5 appears exactly,
  character for character, in SKILL.md, and alongside **every** write call in
  both examples and in the triage guide.

### D. Safety and behavioural correctness
- D1. No file proposes, executes, or implies any action that the wrappers deny
  or that the skill's own hard boundaries forbid (e.g. starting `Dns`, stopping
  `EventLog`, disabling `krbtgt`, touching Default Domain Policy, adding to
  Domain Admins).
- D2. In the examples, every write is preceded by a fresh read of the target and
  followed by an independent verifying read. Every write has a stated rollback.
- D3. Exactly one write per approval card. No write is issued before the
  previous one has returned.
- D4. Denied and expired cards are handled correctly: no automatic
  resubmission, no workaround through another tool.
- D5. No destructive or irreversible action (deletion, password reset, rule
  creation) is recommended through the broker. Operator-only actions are
  clearly labelled.
- D6. Prompt-injection guidance exists and is consistent with the manifest's
  `untrustedInputSources` and the `untrusted-source-cannot-mutate` policy.
- D7. Operator PowerShell snippets are syntactically valid and correct
  (cmdlet names, parameter names, TimeSpan formats such as `00:15:00` and
  `90.00:00:00`), and they do not contradict the skill's own targets.
- D8. Decision trees have no dead ends, no overlapping branches with
  conflicting outcomes, and an escalation path wherever the broker cannot act.

### E. Internal consistency
- E1. The severity counts in the executive summary of `audit-session.md` equal
  the number of rows of each severity in its findings table.
- E2. Date arithmetic is correct. The audit date is 2026-11-11. Check the
  90-day cut-off and every "N days inactive" figure.
- E3. Finding IDs (F-xx), remediation IDs (R-xx), and operator IDs (O-xx) are
  referenced consistently between `audit-session.md` and `remediation-flow.md`.
  Accounts, hosts, task names, correlation IDs, and timestamps are consistent
  across turns (e.g. card expiry ≈ dispatch time + 120 s, change-log times in order).
- E4. Tool output in the examples matches the module output shape: single
  object vs array, and field types (e.g. `LockoutThreshold` int vs string).
- E5. SKILL.md, the CIS map, and the triage guide agree on thresholds (lockout
  1–10 vs CIS ≤ 5, password length 14, max age 90 vs 365) and state every
  difference explicitly.
- E6. The same condition gets the same severity label in every file.

### F. Domain accuracy
- F1. CIS recommendation numbers and titles for Windows Server 2022/2025 are
  plausible. If you can access the official CIS benchmark, check them against
  it. If you cannot, flag any number you believe is wrong and state your
  confidence. Never invent a "correct" number without evidence.
- F2. Windows facts are correct: event ID meanings (4624 Type 9 =
  NewCredentials, 4771 failure code 0x18, 4776 `0xC000006A`, 7045 in the System
  log, 4698, 4697), well-known SIDs, privilege constant names,
  `lastLogonTimestamp` replication lag, FGPP precedence semantics (lower number
  wins), service names (`W3SVC`, `WAS`, `Spooler`, `RemoteRegistry`, `FTPSVC`),
  and default firewall rule names (`IIS-WebServerRole-HTTP-In-TCP`, etc.).
- F3. The security recommendations reflect current practice: PrintNightmare
  Spooler guidance, Potato-family abuse of `SeImpersonatePrivilege`, tiered
  administration, disabling instead of deleting.

### G. Usability as an Agent Skill
- G1. The frontmatter `description` and the trigger section let an agent decide
  when to load the skill. Note likely false positives and false negatives.
- G2. An agent following SKILL.md alone, without the examples, could run each
  SOP end to end without guessing a tool name or parameter.
- G3. The length is reasonable for an agent's context. Point out redundancy
  that could move to `references/` without losing anything.
- G4. All Markdown renders: tables have consistent column counts, code fences
  are closed, JSON blocks are valid JSON, and backslash escaping is consistent
  (`"\\"` in JSON, `\` in prose).

## Output format

Return exactly this structure.

### 1. Verdict
`PASS`, `PASS WITH FIXES`, or `FAIL`, plus one sentence. The verdict is `FAIL`
if any Critical or High finding exists.

### 2. Findings
One row per defect, most severe first:

| # | Severity | Check | File:line | Problem | Evidence (source-of-truth file:line or command output) | Fix |
|---|---|---|---|---|---|---|

Severity:
- **Critical** — the skill would make an agent call a non-existent tool, send
  invalid parameters, propose a denied or unsafe action, or misstate a security
  boundary.
- **High** — wrong output field or rejection reason, broken verbatim string,
  missing verify or rollback step, or a Windows/CIS factual error that changes
  a decision.
- **Medium** — internal inconsistency, arithmetic error, unclear decision branch.
- **Low** — wording, formatting, redundancy.

Every finding needs evidence. A finding you cannot back with evidence goes in
section 4 instead.

### 3. Checklist results
A compact table of every check ID (A1 … G4) with PASS / FAIL / N/A.

### 4. Unverified concerns
Things you suspect but could not prove, each with what would settle it.

### 5. Fix mode (only if the user says "fix")
Apply the minimal edits for every Critical and High finding, and for every
Medium finding whose fix is unambiguous. Edit only files under
`skills/ad-server-hygiene/`. Never edit a source of truth to match the skill.
Afterwards, re-run the automated pass from section B and include its output.
List every edit as `file:line — before → after`.

# Read-tier output inventory

Every read-tier tool, the exact fields its PowerShell wrapper projects, and a sensitivity
classification of each field.

**How this was produced and what it proves.** The field lists are extracted mechanically from the
checked-in wrappers (`jea/modules/Get-Broker*.psm1`) and checked against them, the manifest masks and
the classification file `docs/read-tier-output-schemas.json` by `OutputSchemaInventoryTests` and
`WrapperHygieneTests`. That is **static analysis of source code**. It is not output captured from a real
AD, DNS, DHCP, Hyper-V, IIS or other role: none of these wrappers has been run against a real role in
this repository, so what a given cmdlet actually returns for a given field (for example the shape of a
property the wrapper copies unmodified) is unverified.

## Findings

1. **Every wrapper projects explicitly.** All 49 read wrappers build their result with
   `[pscustomobject]@{ ... }`; none pipes a cmdlet's native object through. A test rejects
   `Select-Object *`, `Format-*`, `ConvertTo-*`, `Out-String` and similar in any wrapper.
2. **No secrets are emitted.** No field is classified `secret`. BitLocker recovery passwords and key
   protector ids are not read by the wrapper at all; the manifest's `KeyProtectorId` /
   `RecoveryPassword` masks are defense in depth for a future wrapper edit, and a test requires every
   mask that names a never-emitted field to be declared as such.
3. **One nested object leaked its whole graph (fixed).** `Get-BrokerNetworkControllerConfig` returned
   `Node = $nc.Node`, an unprojected object. Remote invocation deserializes the full property set and the
   broker flattens all of it. `Node` is now projected to node names. Not exercised against a real Network
   Controller.
4. **A wrapper comment misdescribed its output (fixed).** `Get-BrokerJeaEndpoints` called its output
   "non-sensitive" while returning `RunAsUser` and `Permission`, which name the principals allowed to
   call each endpoint and the identity it runs as. It is classified `security-config`.
5. **Identifiers returned on purpose.** `list-user-rights-assignments.AssignedTo` (SIDs and accounts: the
   whole point of the tool) and `list-ad-organizational-units.DistinguishedName` (an OU's DN is its
   identity and GPO links need it) are not masked. Every other `security-identifier` field is. Masking
   the user DN in `query-ad-user` therefore hides little, because the OU tool reveals the same structure;
   it is kept because it is cheap and consistent.
6. **Attacker-influenceable free text is mostly *not* tagged as an untrusted source (decision, not a bug).**
   VM names, service display names, scheduled task names/authors, share descriptions, printer names,
   firewall display names, WSUS update titles and similar strings can be authored by parties below the
   administrator. Only AD-sourced tools and `list-directory-contents` / `summarize-transcript-logs` are
   tagged, so reading the others does not taint the caller. Tagging them would make the primary
   "list services, then stop one" workflow impossible for 5 minutes after every read, because taint is
   per caller and cannot tell which later parameter came from which earlier output. The control for these
   is the human approver reviewing the exact tool and parameters. 19 tools
   carry an explicit `accepted-untagged` decision, and a test fails if a new read tool returns
   influenceable text without either a tag or such a decision. Revisit this if provenance-aware taint
   tracking is introduced.
7. **Error text is not returned.** `JeaEndpointClient` logs PowerShell error text locally and returns only
   a fixed reject code, so a cmdlet error that echoes a path, account or other value cannot reach a client.

## Classification

| Class | Meaning |
|---|---|
| `operational` | Status values, counters, enums, timestamps, sizes. |
| `object-name` | Names/labels of OS, AD or hypervisor objects (authored by administrators or third parties). |
| `free-text` | Descriptions and other long-form text. |
| `account-identity` | Account names, display names, e-mail addresses, titles, departments. |
| `account-activity` | Last logon, password expiry. |
| `security-identifier` | SIDs, distinguished names, principal lists that contain SIDs. |
| `security-config` | Security policy values, ACL/run-as principal names, certificate thumbprints. |
| `network-identifier` | IP and MAC addresses, scope ids, bindings, URLs, host names. |
| `filesystem-path` | Local or UNC paths and file names. |
| `secret` | Credentials, keys, recovery material. No tool may ever return a field of this class. |

## Tools

Field notation: *(class, masked, untrusted text)*. "untrusted text" marks fields whose content a party
other than the broker's administrator can plausibly author.

| Tool | Fields | Taint treatment |
|---|---|---|
| `list-jea-endpoints` | Name *(object-name)*; RunAsUser *(security-config)*; Permission *(security-config)*; LanguageMode *(operational)* | n/a |
| `query-ad-user` | SamAccountName *(account-identity)*; DisplayName *(account-identity, untrusted text)*; Enabled *(operational)*; LastLogonDate *(account-activity)*; Department *(account-identity, untrusted text)*; Title *(account-identity, untrusted text)*; objectSid *(security-identifier, masked)*; distinguishedName *(security-identifier, masked)* | tagged: ad-attribute |
| `summarize-transcript-logs` | Date *(operational)*; TranscriptCount *(operational)* | tagged: file-content |
| `list-windows-features` | Name *(object-name)*; DisplayName *(object-name)*; Installed *(operational)*; FeatureType *(operational)* | n/a |
| `list-group-policies` | DisplayName *(object-name, untrusted text)*; Id *(object-name)*; GpoStatus *(operational)*; CreationTime *(operational)*; ModificationTime *(operational)* | tagged: ad-attribute |
| `list-iis-sites` | Name *(object-name, untrusted text)*; Id *(operational)*; State *(operational)*; PhysicalPath *(filesystem-path, untrusted text)*; Bindings *(network-identifier, untrusted text)*; ApplicationPool *(operational)* | **untagged** (accepted) |
| `list-ad-computers` | Name *(object-name, untrusted text)*; OperatingSystem *(operational, untrusted text)*; LastLogonDate *(account-activity)*; Enabled *(operational)*; objectSid *(security-identifier, masked)* | tagged: ad-attribute |
| `list-ad-groups` | Name *(object-name, untrusted text)*; GroupCategory *(operational)*; GroupScope *(operational)*; objectSid *(security-identifier, masked)* | tagged: ad-attribute |
| `list-certificate-authorities` | Name *(object-name)*; ComputerName *(network-identifier)*; IsRoot *(operational)*; DisplayName *(object-name)* | n/a |
| `list-adfs-relying-parties` | Name *(object-name)*; Identifier *(object-name)*; Enabled *(operational)* | n/a |
| `list-dhcp-scopes` | ScopeId *(network-identifier)*; Name *(object-name, untrusted text)*; State *(operational)*; StartRange *(network-identifier)*; EndRange *(network-identifier)* | **untagged** (accepted) |
| `list-dns-zones` | ZoneName *(object-name, untrusted text)*; ZoneType *(operational)*; IsDsIntegrated *(operational)*; IsReverseLookupZone *(operational)* | **untagged** (accepted) |
| `list-smb-shares` | Name *(object-name, untrusted text)*; Path *(filesystem-path, untrusted text)*; Description *(free-text, untrusted text)*; ShareType *(operational)* | **untagged** (accepted) |
| `list-disks` | Number *(operational)*; FriendlyName *(object-name)*; SizeBytes *(operational)*; HealthStatus *(operational)*; PartitionStyle *(operational)* | n/a |
| `list-storage-pools` | FriendlyName *(object-name)*; HealthStatus *(operational)*; SizeBytes *(operational)*; AllocatedBytes *(operational)* | n/a |
| `list-hyperv-vms` | Name *(object-name, untrusted text)*; State *(operational)*; CPUUsage *(operational)*; MemoryAssignedBytes *(operational)*; Uptime *(operational)* | **untagged** (accepted) |
| `list-printers` | Name *(object-name, untrusted text)*; DriverName *(object-name, untrusted text)*; PortName *(object-name, untrusted text)*; Shared *(operational)*; PrinterStatus *(operational)* | **untagged** (accepted) |
| `list-rds-collections` | CollectionName *(object-name, untrusted text)*; CollectionType *(operational)*; Size *(operational)* | **untagged** (accepted) |
| `list-wsus-updates` | Title *(object-name, untrusted text)*; Classification *(operational)*; KnowledgeBaseArticles *(operational, untrusted text)*; IsDeclined *(operational)* | **untagged** (accepted) |
| `list-wds-boot-images` | ImageName *(object-name, untrusted text)*; Architecture *(operational)*; FileName *(filesystem-path, untrusted text)* | **untagged** (accepted) |
| `list-cluster-nodes` | Name *(object-name, untrusted text)*; State *(operational)*; DynamicWeight *(operational)* | **untagged** (accepted) |
| `list-bitlocker-volumes` | MountPoint *(object-name)*; VolumeStatus *(operational)*; ProtectionStatus *(operational)*; EncryptionPercentage *(operational)*; defense-in-depth masks (never emitted): KeyProtectorId, RecoveryPassword | n/a |
| `list-firewall-rules` | Name *(security-config, untrusted text)*; DisplayName *(security-config, untrusted text)*; Direction *(security-config)*; Action *(security-config)*; Profile *(security-config)* | **untagged** (accepted) |
| `list-nlb-clusters` | ClusterName *(object-name)*; ClusterIP *(network-identifier)*; ClusterMode *(operational)* | n/a |
| `list-network-adapters` | Name *(object-name)*; Status *(operational)*; LinkSpeed *(operational)*; MacAddress *(network-identifier)*; IPv4Address *(network-identifier)* | n/a |
| `list-windows-services` | Name *(object-name, untrusted text)*; DisplayName *(object-name, untrusted text)*; Status *(operational)*; StartType *(operational)* | **untagged** (accepted) |
| `list-local-users` | Name *(object-name, untrusted text)*; Enabled *(operational)*; LastLogon *(account-activity)*; PasswordExpires *(account-activity)*; SID *(security-identifier, masked)* | **untagged** (accepted) |
| `list-scheduled-tasks` | TaskName *(object-name, untrusted text)*; TaskPath *(object-name, untrusted text)*; State *(operational)*; Author *(account-identity, untrusted text)* | **untagged** (accepted) |
| `list-adlds-instances` | InstanceName *(object-name)*; ServiceName *(object-name)*; Status *(operational)* | n/a |
| `list-rms-superusers` | Email *(account-identity, untrusted text)*; Enabled *(operational)* | **untagged** (accepted) |
| `get-hgs-status` | HgsServerOperationMode *(operational)*; AttestationUrl *(network-identifier)*; KeyProtectionUrl *(network-identifier)* | n/a |
| `get-network-controller-config` | RestIpAddress *(network-identifier)*; Node *(object-name)*; ServerCertificate *(security-config)* | n/a |
| `get-remote-access-status` | VpnStatus *(security-config)*; DAStatus *(security-config)*; RoutingStatus *(security-config)* | n/a |
| `list-storage-migration-jobs` | Name *(object-name, untrusted text)*; State *(operational)* | **untagged** (accepted) |
| `list-system-insights-capabilities` | Name *(object-name)*; Enabled *(operational)* | n/a |
| `get-domain-password-policy` | MinPasswordLength *(security-config)*; MinPasswordAge *(security-config)*; MaxPasswordAge *(security-config)*; PasswordHistoryCount *(security-config)*; ComplexityEnabled *(security-config)*; ReversibleEncryptionEnabled *(security-config)*; LockoutThreshold *(security-config)*; LockoutDuration *(security-config)*; LockoutObservationWindow *(security-config)* | tagged: ad-attribute |
| `list-fine-grained-password-policies` | Name *(security-config, untrusted text)*; Precedence *(security-config)*; MinPasswordLength *(security-config)*; ComplexityEnabled *(security-config)*; LockoutThreshold *(security-config)* | tagged: ad-attribute |
| `get-local-security-policy` | MinimumPasswordAge *(security-config)*; MaximumPasswordAge *(security-config)*; MinimumPasswordLength *(security-config)*; PasswordComplexity *(security-config)*; PasswordHistorySize *(security-config)*; LockoutBadCount *(security-config)*; ResetLockoutCount *(security-config)*; LockoutDuration *(security-config)* | n/a |
| `get-audit-policy` | Subcategory *(security-config)*; AuditCondition *(security-config)* | n/a |
| `list-user-rights-assignments` | Privilege *(operational)*; AssignedTo *(security-identifier)* | n/a |
| `list-local-groups` | Name *(object-name, untrusted text)*; Description *(free-text, untrusted text)*; SID *(security-identifier, masked)* | **untagged** (accepted) |
| `list-local-group-members` | Name *(object-name, untrusted text)*; ObjectClass *(operational)*; PrincipalSource *(operational)* | **untagged** (accepted) |
| `list-ad-organizational-units` | Name *(object-name, untrusted text)*; DistinguishedName *(security-identifier)* | tagged: ad-attribute |
| `list-directory-contents` | Name *(object-name, untrusted text)*; FullName *(filesystem-path, untrusted text)*; IsDirectory *(operational)*; LengthBytes *(operational)*; LastWriteTime *(operational)* | tagged: file-content |
| `list-ftp-sites` | Name *(object-name, untrusted text)*; State *(operational)*; PhysicalPath *(filesystem-path, untrusted text)*; FtpBindings *(network-identifier, untrusted text)* | **untagged** (accepted) |
| `get-execution-policy` | Scope *(security-config)*; ExecutionPolicy *(security-config)* | n/a |
| `get-psremoting-status` | Transport *(operational)*; Address *(network-identifier)*; Port *(operational)*; Enabled *(operational)*; ServiceStatus *(operational)*; StartType *(operational)*; Listeners *(operational)* | n/a |
| `list-read-only-domain-controllers` | Name *(object-name, untrusted text)*; Site *(object-name, untrusted text)*; OperatingSystem *(operational, untrusted text)*; IPv4Address *(network-identifier)* | tagged: ad-attribute |
| `get-applocker-policy` | CollectionType *(security-config)*; EnforcementMode *(security-config)*; RuleCount *(security-config)* | n/a |

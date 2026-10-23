# Security Hardening Guide

## Installation and service identity

- Run the broker under a dedicated gMSA only when domain access is required.
- Use a virtual account for local-only read tools.
- Do not use Domain Admin or Local Administrator as the broker identity.
- Restrict the published executable, manifest, wrapper modules, generated JEA files,
  transcript directory, and correlation log to administrators, the service identity,
  and the required Windows service infrastructure.
- Keep the MCP client SID allowlist minimal. Never use `Everyone` or
  `Authenticated Users` as a shortcut.

## Manifest and module integrity

- Keep `Manifest:RequireIntegrity` enabled.
- Protect both `policy/manifest.json` and its `.sha256` sidecar with NTFS ACLs.
- Generate the sidecar only in a trusted deployment pipeline. Do not allow the broker
  service identity or MCP client to modify policy files.
- Sign wrapper modules with an approved certificate and verify signatures before
  installation.
- Install each module once in a canonical, ACL-protected module directory. Remove
  shadowed duplicate module versions.
- Generate JEA files from the reviewed manifest, review the diff, and register only the
  generated files from the same deployment.
- Treat manifest, policy, wrapper modules, role capabilities, and session configurations
  as one versioned release.

## JEA and least privilege

- Use `RestrictedRemoteServer` and `NoLanguage`.
- Expose only the reviewed wrapper cmdlet for each role capability.
- Keep `VisibleExternalCommands` empty unless a specific wrapper requires an explicitly
  reviewed executable.
- Use gMSA only for tools that require domain/network identity.
- Verify effective role definitions and run-as identity with a low-privilege test account.
- Test prohibited commands and alternate parameter forms, not only successful calls.
- Do not provide an arbitrary PowerShell or script execution tool.

## Approval and operations

- Keep `Elicitation:RequireDistinctApprover` enabled for all write/destructive tools.
- Configure an explicit `ApproverSids` allowlist and protect the approval pipe with its
  own ACL.
- Review the exact tool, parameters, target, caller, and expected impact before approval.
- Treat a disconnect or timeout as an uncertain execution outcome until the underlying
  PowerShell operation is verified stopped.
- Configure explicit `resourceAllowlist` values for every write tool before enabling it.
  Empty resource lists deliberately deny all values.
- Keep rate limits, frame limits, and execution limits conservative.

## Audit and monitoring

- Protect transcript and correlation-log directories from the MCP client.
- Forward ETW and JEA audit events to an independent collector where possible.
- Retain request ID, caller SID, tool, endpoint, approval decision, execution result,
  duration, and cancellation state.
- Do not log passwords, access tokens, or raw sensitive directory attributes.
- Treat ambiguous transcript correlation as an audit failure requiring investigation,
  not as a successful attribution.

## WDAC and deployment

1. Generate and review JEA files.
2. Install signed modules into the canonical directory.
3. Run the broker and wrapper self-checks in a test environment.
4. Deploy WDAC in Audit mode and inspect observed events.
5. Test normal operation and all required-deny cases.
6. Capture a rollback copy of manifest, modules, JEA files, and service configuration.
7. Enable Enforcement only after the rollback path has been tested.

If any signature, manifest integrity, JEA registration, or self-check fails, stop the
deployment. Do not fall back to unrestricted PowerShell or disable a security gate.

## Required integration environment

Before production use, test on isolated Windows Server hosts with the supported roles:
AD DS, DNS/DHCP, IIS, Hyper-V, and local-only Server Manager tools. Include a domain
joined gMSA host, a low-privilege caller, a separately authorized approver, real Named
Pipe ACL checks, registered JEA endpoints, reparse-point filesystem cases, cancellation,
and rollback exercises. Never run these tests against an unapproved production domain.

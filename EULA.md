# END-USER LICENSE AGREEMENT (EULA) & ENTERPRISE TERMS OF USE

**Product**: Windows-Server-MCP Appliance & Agent Skill Suite (`skills/ad-server-hygiene`)  
**Effective Date**: November 2026  
**Version**: 1.0 (Commercial Enterprise Release)

IMPORTANT — READ CAREFULLY: This End-User License Agreement ("**Agreement**" or "**EULA**") is a binding legal contract between the corporate entity, government agency, or individual installing, configuring, deploying, or operating the Software ("**Customer**", "**Licensee**", or "**Operator**") and the commercial licensor and authors of **Windows-Server-MCP** ("**Licensor**").

By downloading, installing, running `deploy/Install-WindowsServerMcp.ps1`, executing `deploy/auto-configure.ps1`, registering the `McpBroker` Windows Service, or connecting any Artificial Intelligence (AI) or Large Language Model (LLM) client to the Software, Customer expressly agrees to be bound by all terms and conditions of this Agreement. If Customer does not agree to every provision of this Agreement, Customer must not install, configure, or operate the Software.

---

## 1. Definitions

1. **"Software"** means the **Windows-Server-MCP** binary executables (`Broker.Host`, `Broker.McpAdapter`, `Broker.ApproverCli`), core libraries (`Broker.Core`, `Broker.Transport`, `Broker.Policy`, `Broker.Registry`, `Broker.JeaExecution`, `Broker.Audit`), Just Enough Administration (JEA) PowerShell wrapper modules (`jea/modules/*.psm1`), generated JEA role capabilities and session configurations (`.psrc`/`.pssc`), policy manifests (`policy/manifest.json`), deployment automation scripts (`deploy/*.ps1`), accompanying agent skills (`skills/ad-server-hygiene`), and documentation.
2. **"AI Agent"** or **"LLM Client"** means any autonomous, semi-autonomous, or interactive software client (including but not limited to Claude Desktop, Cursor, Cline, custom MCP orchestrators, or foundation models) that issues JSON-RPC 2.0 tool requests to the Software via `Broker.McpAdapter` or named pipes.
3. **"Write-Tier / Mutating Operation"** means any tool invocation categorized under `riskTier: "write"` or `riskTier: "destructive"` in `policy/manifest.json` (including all `Set-Broker*` modules and `set-*` tool IDs) that alters the state, configuration, availability, group membership, security policy, or identity directory of a Windows Server or Active Directory environment.
4. **"Human-in-the-Loop Approver"** means a qualified, human systems administrator authorized by Customer who possesses a distinct Windows Security Identifier (`ApproverSids`) separate from the AI Agent caller identity (`CallerSids`) and who explicitly reviews and approves or denies pending Write-Tier Operations over the out-of-band approval pipe (`\\.\pipe\McpBroker.Approvals`).

---

## 2. Commercial License Grant & Restrictions

### 2.1 Grant of License
Subject to the terms and conditions of this Agreement and timely payment of applicable commercial subscription or enterprise licensing fees, Licensor grants Customer a non-exclusive, non-transferable, non-sublicensable, revocable license to install and execute the Software on Windows Server instances owned, leased, or controlled by Customer solely for Customer's internal enterprise IT administration, security auditing, and Active Directory hygiene operations.

### 2.2 License Restrictions
Customer shall not, and shall not permit any employee, contractor, AI Agent, or third party to:
1. Bypass, disable, patch, stub, or circumvent any security gate in the 8-gate broker pipeline, including Authenticode signature verification (`WinVerifyTrust`), manifest SHA-256 integrity checks, parameter allowlists, caller taint tracking, or distinct-approver human elicitation (`RequireDistinctApprover`).
2. Configure overlapping Security Identifiers between `Pipe:AllowedSids` and `Elicitation:ApproverSids` in production, or automate responses to `Broker.ApproverCli` / `\\.\pipe\McpBroker.Approvals` using scripts, bots, or secondary AI agents ("Auto-Approval Bypass").
3. Modify JEA Role Capabilities (`.psrc`) or Session Configurations (`.pssc`) to grant access to broad security principals (`Everyone`, `Authenticated Users`, `BUILTIN\Users`, `Domain Users`) or enable unrestricted PowerShell language modes (`FullLanguage`).
4. Redistribute, resell, lease, sublicense, or offer the Software as a managed commercial service (MSP/SaaS) to third parties without a separate written Commercial OEM/MSP Distribution Agreement with Licensor.

---

## 3. Mandatory Human-in-the-Loop Operator Responsibility Clause

> ### ⚠️ CORE OPERATOR LIABILITY MANDATE / 核心維運責任聲明
> 
> **中文法定聲明：**  
> 「本 AI Agent Skill 僅提供維運決策輔助與合規建議。所有變更操作之最終法律與維運責任，歸屬於在 Broker.ApproverCli 終端中按下確認審批的人類操作員。」
> 
> **English Legal Statement:**  
> "This AI Agent Skill and Windows-Server-MCP broker provide operational decision support and configuration recommendations only. All legal, compliance, and operational liability for mutating system changes remains exclusively with the human operator authorizing the execution card in the Broker.ApproverCli terminal."

### 3.1 AI Probabilistic Nature & Hallucination Risk
Customer acknowledges and agrees that Large Language Models (LLMs) and AI Agents are inherently probabilistic systems capable of generating inaccurate interpretations, hallucinated parameters, misidentified Active Directory objects, or unintended operational sequences—including when processing untrusted host metadata (such as service descriptions, event logs, or LDAP attributes that may contain adversarial prompt injections).

### 3.2 Sole Operator Responsibility for Mutating Actions
The Software enforces an architecture where all 13 Write-Tier tools (`set-scheduled-task-state`, `set-windows-service-state`, `set-firewall-rule-enabled`, `set-local-user-enabled`, `set-hyperv-vm-state`, `set-iis-site-state`, `set-cluster-node-state`, `set-wsus-update-approval`, `set-ad-user-enabled`, `set-ad-computer-enabled`, `set-ad-group-membership`, `set-gpo-status`, and `set-dhcp-scope-state`) require interactive human authorization over a segregated named pipe (`\\.\pipe\McpBroker.Approvals`).

**CUSTOMER EXPRESSLY AGREES THAT:**
1. **Every Approved Action is an Operator Act**: Whenever a Human-in-the-Loop Approver authorizes a pending request via `Broker.ApproverCli` (or any client connected to `McpBroker.Approvals`), that authorization constitutes the deliberate, independent administrative command of Customer's human operator, exactly as if the human operator had typed and executed the underlying PowerShell command directly on the server console.
2. **Duty of Pre-Approval Verification**: Prior to granting approval (`[y/N]`), Customer's Human-in-the-Loop Approver bears the sole and non-delegable duty to verify:
   - The exact `Tool ID` and `CorrelationId`;
   - Every target resource identifier (e.g., `SamAccountName`, `DistinguishedName`, `ServiceName`, `GpoGuid`, `ScopeId`, `VmName`, `NodeName`);
   - The business and operational impact on domain replication, authentication availability, network routing, cluster quorum, and dependent workloads; and
   - The existence of a tested rollback plan and current Active Directory System State backup.
3. **Prohibition on Unattended Write Execution**: Customer assumes 100% of the operational, security, and financial risk if Customer enables `-DevMode` in a production environment, disables `RequireDistinctApprover`, shares credentials between caller and approver sessions, or permits any unattended automation to approve Write-Tier Operations.

---

## 4. Production Deployment Prerequisites & Customer Obligations

Before deploying the Software in any production or business-critical environment, Customer is solely responsible for:
1. **Enterprise PKI & Code Signing**: Issuing and managing code-signing certificates through a secured Active Directory Certificate Services (AD CS) or enterprise PKI hierarchy in accordance with `docs/adcs-code-signing-guide.md`, and protecting private signing keys in hardware security modules (HSMs) or non-exportable machine key stores.
2. **Explicit Resource Scoping**: Populating explicit `resourceAllowlist` boundaries in `policy/manifest.json` and regenerating `policy/manifest.json.sha256` within a trusted, off-host release pipeline before enabling any Write-Tier tool.
3. **Least-Privilege Service Identity**: Running `Broker.Host` under a dedicated Group Managed Service Account (gMSA) with minimal delegated Active Directory permissions, never under `Domain Admins`, `Enterprise Admins`, or interactive user accounts.
4. **Isolated Staging Validation**: Validating all JEA endpoints, WDAC policies (`deploy/setup-wdac.ps1`), and role-specific cmdlet behaviors in a non-production staging domain prior to production rollout.

---

## 5. Disclaimer of Warranties ("AS-IS")

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE SOFTWARE, JEA MODULES, DEPLOYMENT SCRIPTS, AGENT SKILLS, AND DOCUMENTATION ARE PROVIDED **"AS IS"** AND **"AS AVAILABLE"**, WITH ALL FAULTS AND WITHOUT WARRANTY OF ANY KIND.

LICENSOR EXPRESSLY DISCLAIMS ALL WARRANTIES, WHETHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT, HIGH AVAILABILITY, OR ERROR-FREE OPERATION. LICENSOR DOES NOT WARRANT THAT:
1. THE SOFTWARE WILL PREVENT ALL PROMPT INJECTIONS, PRIVILEGE ESCALATIONS, OR UNAUTHORIZED MODIFICATIONS;
2. AI AGENTS USING THE SOFTWARE OR THE `ad-server-hygiene` SKILL WILL MAKE ACCURATE DIAGNOSTIC OR REMEDIATION RECOMMENDATIONS; OR
3. EXECUTION OF ANY READ-TIER OR WRITE-TIER TOOL WILL NOT DISRUPT ACTIVE DIRECTORY DOMAIN SERVICES, DNS/DHCP RESOLUTION, FAILOVER CLUSTERS, HYPER-V VIRTUAL MACHINES, IIS WEBSITES, OR WINDOWS SERVER AVAILABILITY.

> **HIGH-RISK SYSTEMS NOTICE**: The Software is not fault-tolerant and is not designed, manufactured, or intended for use in hazardous environments requiring fail-safe performance (including nuclear facilities, aircraft navigation, air traffic control, life-support machines, or critical emergency dispatch systems) where failure or misconfiguration of a Windows Server could lead directly to death, personal injury, or severe physical or environmental damage.

---

## 6. Limitation of Liability

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW:

1. **EXCLUSION OF CONSEQUENTIAL & INDIRECT DAMAGES**: IN NO EVENT SHALL LICENSOR, ITS AFFILIATES, AUTHORS, CONTRIBUTORS, OR LICENSORS BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, EXEMPLARY, OR PUNITIVE DAMAGES, INCLUDING WITHOUT LIMITATION DAMAGES FOR:
   - DOMAIN CONTROLLER OUTAGES, ACTIVE DIRECTORY CORRUPTION, OR KERBEROS/LDAP AUTHENTICATION FAILURES;
   - ACCOUNT LOCKOUTS, PRIVILEGE MISCONFIGURATIONS, OR GROUP POLICY (GPO) DISRUPTIONS;
   - LOSS OF DATA, LOSS OF REVENUE, LOSS OF PROFITS, BUSINESS INTERRUPTION, OR COST OF PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; OR
   - CYBERSECURITY INCIDENTS, RANSOMWARE, OR UNAUTHORIZED ACCESS ARISING FROM MISCONFIGURED SID ALLOWLISTS, COMPROMISED APPROVER ACCOUNTS, OR SELF-SIGNED CERTIFICATES,
   HOWEVER CAUSED AND UNDER ANY THEORY OF LIABILITY (WHETHER IN CONTRACT, STRICT LIABILITY, TORT, INCLUDING NEGLIGENCE, OR OTHERWISE), EVEN IF LICENSOR HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
2. **CAP ON TOTAL AGGREGATE LIABILITY**: LICENSOR'S TOTAL CUMULATIVE LIABILITY ARISING OUT OF OR RELATED TO THIS AGREEMENT OR THE USE OR INABILITY TO USE THE SOFTWARE SHALL NOT EXCEED THE GREATER OF: (A) THE TOTAL COMMERCIAL LICENSE FEES ACTUALLY PAID BY CUSTOMER TO LICENSOR FOR THE SOFTWARE IN THE TWELVE (12) MONTHS IMMEDIATELY PRECEDING THE EVENT GIVING RISE TO LIABILITY, OR (B) ONE HUNDRED UNITED STATES DOLLARS (US $100.00).

---

## 7. Indemnification by Customer

Customer agrees to defend, indemnify, and hold harmless Licensor, its officers, directors, employees, authors, and contributors from and against any and all third-party claims, regulatory fines, audits, liabilities, damages, losses, and expenses (including reasonable attorneys' fees) arising out of or connected with:
1. Customer's deployment, configuration, or operation of the Software in Customer's infrastructure;
2. Any Write-Tier Operation approved by Customer's Human-in-the-Loop Approver (or executed due to Customer's disabling or circumvention of distinct-approver elicitation);
3. Customer's violation of Section 2 (Restrictions), Section 3 (Human-in-the-Loop Operator Responsibility), or Section 4 (Production Prerequisites); or
4. Any breach of data privacy, security compliance, or change-management regulations caused by Customer's use of AI Agents against production directory or server systems.

---

## 8. Audit Logs, Telemetry & Compliance Retention

The Software generates local structured Event Tracing for Windows (ETW) events, JSONL correlation logs (`C:\McpBroker\logs\correlation.log`), and PowerShell JEA session transcripts (`C:\McpBroker\Transcripts`). The Software does **not** transmit telemetry or directory data back to Licensor. Customer is solely responsible for securing, forwarding (to an immutable SIEM/log collector), and retaining these audit records in accordance with Customer's legal, regulatory, and compliance obligations (e.g., SOC 2, ISO 27001, PCI-DSS, HIPAA, GDPR).

---

## 9. Governing Law, Severability & Entire Agreement

1. **Severability**: If any provision of this Agreement is held to be unenforceable or invalid by a court of competent jurisdiction, that provision shall be enforced to the maximum extent permissible and the remaining provisions shall remain in full force and effect.
2. **No Waiver**: Failure by Licensor to enforce any right or provision of this Agreement shall not constitute a waiver of future enforcement of that right or provision.
3. **Entire Agreement**: This Agreement (together with any executed Commercial Enterprise Order Form referencing this Agreement) constitutes the complete and exclusive agreement between Customer and Licensor regarding the Software and supersedes all prior oral or written proposals or understandings.

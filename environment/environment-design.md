# Synthetic SOC Telemetry Environment - Design Document

**Purpose:** Define a fictitious enterprise environment as the basis for generating synthetic security telemetry (CSV, destined for Azure Data Explorer) used for detection engineering practice, SOC analyst training, and correlation/hunting exercises. No real data, no real IOCs, no operational attack tooling - this is a data-modeling exercise.

Fictitious company: **"Contoso Meridian"**  A mid-size financial services firm (~2,500 employees), HQ + 2 branch offices + hybrid cloud (Azure AD / Entra ID + AWS).

---

## A. Enterprise Architecture

### A.1 Users (~2,500 total, modeled as archetypes)
| Archetype | Count | Notes |
|---|---|---|
| Standard office staff | 1,800 | Finance, HR, ops, sales |
| Developers/Engineers | 250 | Access to code repos, CI/CD, cloud consoles |
| IT/Helpdesk | 60 | Elevated local admin rights on subset of hosts |
| Domain/Cloud Admins | 15 | Tier-0 credentials, PAM-vaulted |
| Executives (VIPs) | 25 | High-value phishing/BEC targets |
| Finance/AP (wire-transfer authority) | 40 | BEC/fraud targets |
| Contractors/Vendors | 150 | Time-limited accounts, VPN-only |
| Service/Break-glass accounts | ~30 | Enumerated below |

Naming convention: `first.last@contosomeridian.com`; SAM account `flast`. Each user has: department, title, manager, office location, employment start date, MFA-enrolled flag, privileged flag, badge ID.

### A.2 Groups
- **Security groups:** `SG-DomainAdmins`, `SG-ServerAdmins`, `SG-HelpdeskL1/L2`, `SG-Developers`, `SG-Finance-AP`, `SG-Executives`, `SG-VPN-Users`, `SG-RDP-Allowed`, `SG-CloudAdmins-Azure`, `SG-CloudAdmins-AWS`
- **Distribution groups:** per-department mailing lists
- **Entra ID (Azure AD) roles:** Global Admin, Privileged Role Admin, Application Admin, User Admin, Conditional Access Admin
- **AWS IAM groups:** `iam-admins`, `s3-readonly`, `ec2-devops`, `billing-readonly`

### A.3 Hosts (endpoints, ~2,500)
- Windows 11 corporate laptops (majority), Windows 10 legacy subset (finance dept — unpatched by design)
- macOS laptops (engineering, ~150)
- Shared kiosk workstations in branch offices (higher-risk, shared logins)
- Naming: `CM-LT-{dept}-{####}` (laptops), `CM-WS-{branch}-{####}` (desktops)
- Each host: OS build, EDR agent status, last patch date, primary user, asset criticality tier, subnet

### A.4 Servers (~120)
- File servers (`CM-FS01/02`), print servers, SQL servers (`CM-SQL-FIN01`, `CM-SQL-HR01`), web/app servers, Exchange hybrid server, jump hosts/bastions, backup servers, SCCM/Intune management server, PKI/CA server
- Segregated into Tier 0 (DCs, PKI, PAM), Tier 1 (servers/apps), Tier 2 (workstations)

### A.5 Domain Controllers
- `CM-DC01` (HQ, PDC emulator), `CM-DC02` (HQ, secondary), `CM-DC-BR1` (Branch 1 RODC), `CM-DC-BR2` (Branch 2 RODC)
- Forest: `contosomeridian.local`; hybrid-joined to Entra ID via Azure AD Connect (`CM-AADC01`)

### A.6 Service Accounts
- `svc-sql-fin`, `svc-backup`, `svc-sccm`, `svc-iis-portal`, `svc-adconnect`, `svc-vulnscan`, `svc-monitoring`, `svc-exchange`, `svc-ldapbind`, `svc-rpa-finance` — each with defined SPNs (some deliberately Kerberoastable for scenario design), password-last-set age, and interactive-logon-allowed flag (should be `false` for all, with 1–2 misconfigured as the seed for a detection scenario).

### A.7 Cloud Resources
- **Azure:** Subscription with resource groups for Prod/Dev/Sec-tooling; Storage accounts (one with public-blob misconfig seeded), Key Vault, App Services, VMs, Log Analytics workspace, Sentinel (or ADX) as the SIEM backend, Conditional Access policies, PIM for role activation
- **AWS:** Single account, S3 buckets (one intentionally misconfigured), EC2 fleet (dev sandbox), IAM users/roles, CloudTrail enabled, GuardDuty enabled
- **SaaS:** Microsoft 365 (Exchange Online, SharePoint, Teams), Salesforce, GitHub Enterprise, Okta (secondary IdP for SaaS SSO — optional)

### A.8 Network Segments
- `10.10.0.0/16` — HQ corporate LAN (VLANs per department)
- `10.20.0.0/24` — Server/Datacenter VLAN
- `10.30.0.0/16` — Branch office 1
- `10.40.0.0/16` — Branch office 2
- `10.50.0.0/24` — Guest Wi-Fi (isolated)
- `10.60.0.0/24` — OT/print/IoT VLAN (legacy protocols, minimal monitoring — good for lateral movement scenarios)
- `172.16.0.0/24` — VPN client pool
- `192.168.100.0/24` — Azure VNet (peered), `192.168.200.0/24` — AWS VPC
- Perimeter: firewall, proxy (forces all egress through web proxy w/ TLS inspection), DMZ for public-facing web apps

### A.9 Security Controls
- EDR (e.g., Defender for Endpoint-style) on all managed endpoints
- Windows Event Log forwarding via WEF to central collector
- Sysmon deployed with a standard config (process creation, network, DNS query logging enabled)
- Domain firewall + NGFW at perimeter, IDS/IPS inline
- Web proxy w/ full URL + category logging
- Email security gateway (attachment sandboxing, URL rewriting)
- Entra ID Conditional Access (MFA-required, location/risk-based)
- Azure AD Identity Protection (risky sign-in scoring)
- CASB for SaaS
- PAM/vault for Tier-0 credentials (most admins should use it; 1–2 exceptions = detection gaps by design)
- DLP on email/endpoint
- Vulnerability scanner (authenticated scans, monthly)
- SIEM ingesting all of the above (this is what we're building telemetry for)

---

## B. Telemetry Architecture

Each source below becomes one CSV table for ADX, with a defined schema. Timestamps in UTC, ISO 8601.

### B.1 Windows Security Events (via Sysmon + native Security log)
`WindowsEvents`: `TimeGenerated, EventID, Computer, SubjectUserName, SubjectDomainName, TargetUserName, LogonType, LogonId, IpAddress, ProcessName, ProcessId, ParentProcessName, ParentProcessId, CommandLine, Hashes(SHA256), ImageLoaded, DestinationIp, DestinationPort, TargetObject, TicketOptions, ServiceName, Status`
Key EventIDs modeled: 4624/4625 (logon/fail), 4634 (logoff), 4672 (special privileges), 4688 (process creation), 4697 (service install), 4698 (scheduled task), 4720/4726 (account create/delete), 4732/4728 (group membership), 4768/4769/4770 (Kerberos TGT/TGS/renew), 5140/5145 (network share access), Sysmon 1/3/7/11/22 (process/net/imageload/filecreate/dns)

### B.2 Authentication / Identity (Entra ID Sign-in + Audit Logs)
`AADSignInLogs`: `TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location(City/Country), DeviceDetail, ClientAppUsed, ConditionalAccessStatus, RiskLevelDuringSignIn, RiskState, AuthenticationRequirement, ResultType, ResultDescription, CorrelationId`
`AADAuditLogs`: `TimeGenerated, OperationName, InitiatedBy, TargetResources, Result, Category`

### B.3 EDR Telemetry
`EDRAlerts`: `TimeGenerated, DeviceId, DeviceName, AlertId, Severity, Category(e.g. Execution/Persistence), Title, MitreTechnique, FileName, FileHash, ProcessCommandLine, RemoteIP, RemoteUrl, ActionTaken, InitiatingUser`

### B.4 Network / Firewall / Proxy
`FirewallLogs`: `TimeGenerated, SrcIP, SrcPort, DstIP, DstPort, Protocol, Action(Allow/Deny), Rule, BytesSent, BytesReceived, Direction`
`ProxyLogs`: `TimeGenerated, SrcIP, User, URL, Domain, Category, Action, HTTPMethod, StatusCode, BytesSent, BytesReceived, UserAgent, TLSSNI`
`DNSLogs`: `TimeGenerated, ClientIP, QueryName, QueryType, ResponseCode, ResponseIPs`

### B.5 Email Security
`EmailEvents`: `TimeGenerated, MessageId, SenderAddress, SenderIP, RecipientAddress, Subject, AttachmentNames, AttachmentSHA256, URLs, SPFResult, DKIMResult, DMARCResult, ThreatType, DeliveryAction`

### B.6 Cloud Audit — Azure
`AzureActivityLogs`: `TimeGenerated, Caller, CallerIPAddress, OperationName, ResourceGroup, ResourceId, ActivityStatus, Level`
`AzureKeyVaultLogs`, `AzureStorageLogs`: access/operation-level detail

### B.7 Cloud Audit — AWS
`CloudTrailLogs`: `TimeGenerated, EventName, EventSource, AWSRegion, SourceIPAddress, UserIdentityType, UserIdentityArn, UserAgent, RequestParameters, ResponseElements, ErrorCode`
`GuardDutyFindings`: `TimeGenerated, FindingType, Severity, Resource, Description`

### B.8 SaaS / Collaboration
`M365AuditLogs` (SharePoint/OneDrive/Teams): `TimeGenerated, Operation, UserId, ObjectId(file/site), ClientIP, ItemType, SiteUrl`

### B.9 VPN / Remote Access
`VPNLogs`: `TimeGenerated, User, SrcIP(public), AssignedIP, Duration, BytesIn/Out, ConnectionResult, ClientOS`

### B.10 Endpoint/Asset Inventory (reference/dimension table, not event stream)
`AssetInventory`: `Hostname, IPAddress, OS, PrimaryUser, Criticality, EDRStatus, LastPatchDate, Department, Subnet`

### B.11 Identity Dimension Table (reference)
`UserDirectory`: `UserPrincipalName, SamAccountName, DisplayName, Department, Title, Manager, PrivilegedFlag, MFAEnrolled, EmploymentStatus, StartDate`

### B.12 Vulnerability Scan Results (reference/periodic)
`VulnScans`: `ScanDate, Hostname, CVE, Severity, Status(Open/Patched)`

---

## C. Attack Scenarios (10)

Each scenario is designed to be generated as a coherent, multi-source event sequence embedded within the benign noise.

**1. Phishing → Credential Harvest → BEC Wire Fraud**
- Initial access: Spear-phish to Finance/AP user, credential-harvesting link (T1566.002)
- Chain: Email click → fake O365 login → stolen credential → cloud sign-in from foreign IP → mailbox rule creation to hide replies (T1114.003) → fraudulent wire-transfer email sent to real vendor contact
- Techniques: T1566.002, T1078.004, T1114.003, T1586
- Affected users: 1 AP user, spoofed vendor contact
- Affected hosts: none (cloud-only)
- Telemetry: EmailEvents, AADSignInLogs (impossible travel), AADAuditLogs (inbox rule), M365AuditLogs
- Initial alert: Impossible-travel sign-in risk detection
- Difficulty: Medium (looks like normal mail activity until the rule + wire request correlate)

**2. Kerberoasting for Lateral Movement**
- Initial access: Low-priv developer account compromised via reused password (T1078)
- Chain: Enumerate SPNs (T1087) → request TGS for `svc-sql-fin` (T1558.003) → offline crack (not modeled, implied) → authenticate as service account → access finance SQL server → dump credentials (T1003)
- Techniques: T1087, T1558.003, T1078, T1003.001
- Affected users: 1 developer, `svc-sql-fin`
- Affected hosts: `CM-SQL-FIN01`, developer laptop
- Telemetry: WindowsEvents (4769 spike, unusual TGS encryption type RC4), EDRAlerts
- Initial alert: Multiple 4769 events for same source in short window (Kerberoasting detection rule)
- Difficulty: Medium-Hard (needs baseline of normal TGS request volume)

**3. Ransomware via RDP Brute Force**
- Initial access: Internet-exposed RDP jump host, brute force (T1110.001)
- Chain: Successful brute-force login → disable Defender (T1562.001) → lateral movement via SMB/PsExec (T1021.002) → mass file encryption on file server (T1486) → shadow copy deletion (T1490)
- Techniques: T1110.001, T1562.001, T1021.002, T1486, T1490
- Affected users: 1 service/admin account
- Affected hosts: jump host, `CM-FS01`, 15+ workstations
- Telemetry: WindowsEvents (4625 spike then 4624 success, 4688 vssadmin/wmic), FirewallLogs, EDRAlerts
- Initial alert: EDR ransomware behavior alert (mass file modification)
- Difficulty: Easy once triggered, but brute-force phase easily missed if RDP logs aren't monitored

**4. Insider Data Exfiltration**
- Initial access: N/A - legitimate disgruntled employee (HR dept, resignation pending)
- Chain: Off-hours access to HR SharePoint beyond normal scope (T1213) → bulk download of PII files → upload to personal cloud storage via browser (T1567.002) → USB copy as backup channel (T1052.001)
- Techniques: T1213, T1567.002, T1052.001
- Affected users: 1 HR employee
- Affected hosts: employee laptop
- Telemetry: M365AuditLogs (bulk download), ProxyLogs (personal cloud upload), EDRAlerts (USB device event)
- Initial alert: DLP policy match on bulk PII download
- Difficulty: Hard (activity individually looks legitimate; volume/timing is the signal)

**5. Cloud Storage Misconfiguration Exploited (AWS S3)**
- Initial access: External recon discovers public S3 bucket (T1596)
- Chain: Anonymous `ListBucket`/`GetObject` calls from unknown external IP → bulk download of customer data
- Techniques: T1596.002, T1530
- Affected users: none (external actor), bucket owner (DevOps) implicated in root cause
- Affected hosts: none
- Telemetry: CloudTrailLogs (anonymous access), GuardDutyFindings (S3 exfiltration finding)
- Initial alert: GuardDuty "S3 anomalous access" finding
- Difficulty: Easy to detect, hard to attribute (no authenticated identity)

**6. Golden Ticket / Domain Compromise**
- Initial access: Prior compromise of a Tier-0 admin workstation (assume as given/off-screen)
- Chain: Dump `krbtgt` hash via DCSync (T1003.006) → forge Golden Ticket → authenticate as arbitrary user without touching DC logon (T1558.001) → access multiple servers over following days
- Techniques: T1003.006, T1558.001, T1550
- Affected users: `krbtgt`, multiple impersonated identities
- Affected hosts: `CM-DC01`, multiple servers
- Telemetry: WindowsEvents (4662 on DC replicating-directory-changes, anomalous 4768 with unusual ticket lifetime)
- Initial alert: DCSync detection (4662 with replication GUIDs from non-DC host)
- Difficulty: Very Hard (minimal telemetry footprint, requires DC auditing configured correctly)

**7. Business Email Compromise via OAuth Consent Phishing**
- Initial access: Malicious OAuth app consent grant (T1528)
- Chain: User grants "read mail" permission to attacker-registered Azure AD app → app persistently reads mailbox via Graph API without further sign-ins → attacker monitors for invoice threads → injects fraudulent payment details
- Techniques: T1528, T1114
- Affected users: 1 executive
- Affected hosts: none
- Telemetry: AADAuditLogs (consent grant event), M365AuditLogs (Graph API mail read pattern), EmailEvents
- Initial alert: Risky OAuth app consent detection
- Difficulty: Hard (no further sign-in events after initial consent — persistence is invisible to login-based detections)

**8. Supply Chain / CI-CD Compromise**
- Initial access: Compromised developer GitHub PAT (leaked in public repo) (T1552.001)
- Chain: Attacker uses PAT to push malicious commit to CI pipeline → pipeline auto-deploys to Azure App Service → webshell planted (T1505.003) → used to pivot into Azure subscription via managed identity
- Techniques: T1552.001, T1195.002, T1505.003, T1078.004
- Affected users: 1 developer
- Affected hosts: build agent, App Service
- Telemetry: AzureActivityLogs (deployment event off-hours), EDRAlerts (webshell behavior), AADSignInLogs
- Initial alert: Anomalous deployment time + new outbound connection from App Service
- Difficulty: Hard (legitimate CI/CD activity provides cover)

**9. Living-off-the-Land Lateral Movement (Post-Phish)**
- Initial access: Malicious macro-enabled document (T1566.001) opened by branch-office user
- Chain: Macro spawns PowerShell (T1059.001) → downloads stage-2 via DNS TXT record (T1071.004) → uses WMI for lateral movement to nearby workstation (T1047) → establishes scheduled task persistence (T1053.005)
- Techniques: T1566.001, T1059.001, T1071.004, T1047, T1053.005
- Affected users: 1 branch office user, 1 secondary user
- Affected hosts: 2 workstations in Branch 1
- Telemetry: EmailEvents, WindowsEvents (4688 powershell.exe w/ encoded command, Sysmon 1/22 DNS), EDRAlerts
- Initial alert: EDR suspicious PowerShell encoded-command alert
- Difficulty: Medium

**10. Privileged Access Abuse via Unmanaged Break-Glass Account**
- Initial access: N/A — misuse of legitimate but poorly monitored break-glass admin account (excluded from Conditional Access by design)
- Chain: Account used outside of documented emergency-use policy → logs into Azure Portal from unrecognized device/location → creates new Global Admin account (T1136.003) → modifies Conditional Access policy to weaken MFA requirement (T1556.006)
- Techniques: T1136.003, T1556.006, T1078.004
- Affected users: break-glass account, newly created rogue admin
- Affected hosts: none
- Telemetry: AADAuditLogs (CA policy change, new admin creation), AADSignInLogs
- Initial alert: "Break-glass account used" governance alert (should almost never fire — high-fidelity signal)
- Difficulty: Easy to detect *if* break-glass usage is monitored (a common real-world gap — intentionally included)

---

## D. Benign Activity (background noise)

To make detection non-trivial, generate realistic volume of ordinary activity across the same schemas:
- **Auth patterns:** daily 8-9am login wave, lunchtime badge/VPN dip, normal MFA prompts, occasional genuine mistyped-password failures (1–3 per user per month), legitimate travel-based logins for a subset of users (sales/execs)
- **Process/endpoint noise:** routine app launches (Office, Teams, Chrome, Slack), scheduled patch/update tasks, normal PowerShell use by IT/DevOps (unencoded, signed scripts), routine service restarts
- **Network noise:** normal SaaS traffic (O365, Salesforce, GitHub), streaming/news sites hitting proxy category filters (not blocked), normal DNS resolution patterns, regular backup jobs at night, vulnerability scanner sweeping subnets monthly (should itself resemble "recon" and be a good false-positive teaching case)
- **Email noise:** normal internal/external business correspondence, legitimate marketing emails, occasional benign spam caught by the gateway, calendar invites
- **Cloud noise:** routine IaC deployments during business hours, normal S3/Blob read/write from applications, scheduled Lambda/Function executions, routine IAM role assumption by automation
- **Admin noise:** legitimate PAM-checkout admin sessions, scheduled AD group membership changes (onboarding/offboarding), patch Tuesday reboots
- **Helpdesk noise:** password resets, account unlocks, software install requests - genuine 4720/4724/4767 events unrelated to any attack

Recommended ratio: benign:malicious event volume roughly 500:1 to 2000:1 depending on the table, mirroring real SOC signal-to-noise.

## E. Correlation Model

Core entity graph, all tables should carry keys that allow joins in ADX:

- **User ↔ Host:** `PrimaryUser` in AssetInventory joins to `SubjectUserName`/`TargetUserName` in WindowsEvents; a user may log into multiple hosts (helpdesk shared machines, RDP jump hosts) - model this explicitly for a few "hub" hosts.
- **User ↔ IP:** AADSignInLogs and VPNLogs both carry `User` + `IPAddress`; a user's IP should be consistent with their assigned VPN pool / office subnet / occasional legitimate remote IP, with attack scenarios deliberately breaking this pattern (impossible travel, Tor/VPS ranges).
- **Host ↔ IP:** AssetInventory is the canonical host→IP mapping; DHCP lease changes should occasionally reassign IPs (introduce mild realism/challenge) but keep most hosts on static-ish internal IPs.
- **Process/Session correlation:** Sysmon `LogonId` ties process creation (event 1) to the originating logon session (event 4624), which ties back to `SubjectUserName` - this chain is essential for tracing lateral movement (e.g., Scenario 3, 6, 9).
- **Cloud identity ↔ on-prem identity:** `UserPrincipalName` (Entra ID) maps 1:1 to `SamAccountName` (on-prem AD) via the hybrid identity table — essential for BEC/OAuth scenarios that need to connect a cloud sign-in back to an on-prem account context (e.g., is this a privileged on-prem account too?).
- **Email ↔ Identity ↔ Endpoint:** `RecipientAddress` in EmailEvents → `UserPrincipalName` → device the user opens the message on (`DeviceId` in EDRAlerts) → completes phishing-to-execution chains (Scenarios 1, 9).
- **Network flow chaining:** FirewallLogs/ProxyLogs `SrcIP`/`DstIP` should be joinable to AssetInventory for internal hosts and left as raw external IPs otherwise (a small curated pool of "attacker infrastructure" IPs/domains reused across relevant malicious events for consistency).
- **CorrelationId/SessionId:** consider adding a synthetic `CampaignId` (hidden ground-truth column, not exposed as a "cheat" field in the training exercise but useful for the generator/answer key) that tags every event belonging to a given attack scenario instance, so scenario coherence can be validated programmatically before export.

## F. Dataset Generation Architecture

1. **Ground-truth layer:** Define entities (users, hosts, service accounts, IPs, cloud resources) once as reference tables/dictionaries — single source of truth referenced by every generator function.
2. **Timeline engine:** Generate a shared master timeline (e.g., 30-90 days). Benign activity is generated first as a continuous baseline per entity (daily patterns, weekday/weekend variation, a few holidays). Attack scenarios are then injected as sub-timelines at randomized (but plausible e.g., business hours for phishing, off-hours for exfil) start points, with each scenario's chain generating coherent, causally-ordered events across the relevant schemas with realistic time deltas between steps (seconds for process spawning, hours for later-stage exfil).
3. **Per-scenario event generators:** One function per scenario producing rows for every telemetry table it touches, parameterized by which user/host/IP instance to use (drawn from ground truth), so the same scenario "template" can be replayed multiple times with different entities if more incident volume is wanted later.
4. **Noise generator:** Statistical/probabilistic models (Poisson-ish arrival for logons, normal distribution around a login-time mean, weighted random choice for URL categories, etc.) rather than pure uniform-random, so the data has realistic clustering instead of looking flat/synthetic.
5. **Consistency pass:** After generation, validate referential integrity (every SubjectUserName exists in UserDirectory, every IP used by an internal host matches AssetInventory unless intentionally external/attacker infra, timestamps are monotonic within a session).
6. **Ground-truth/answer key export:** Separate hidden CSV (`ground_truth_labels.csv`) mapping `CampaignId` → scenario name, affected entities, and the "correct" MITRE techniques — used to grade detection exercises without polluting the analyst-facing data.
7. **Export layer:** One CSV per schema table (Section B), consistent column ordering, UTC ISO 8601 timestamps, sized appropriately for ADX ingestion (chunk if needed). Column types documented alongside for `.create table` KQL statements.
8. **Reproducibility:** Seeded RNG so the same design regenerates identically; a config file (users/hosts count, day range, scenario list/frequency) drives the generator so scale can be adjusted without rewriting logic.

---

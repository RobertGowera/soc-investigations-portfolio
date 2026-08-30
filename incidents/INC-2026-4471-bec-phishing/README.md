# INC-2026-4471 — Business Email Compromise via Credential Phishing

**Analyst:** [Your Name]
**Date of Investigation:** [Date]
**Environment:** Contoso Meridian (synthetic financial services enterprise, self-built dataset — 500 users, hybrid Azure AD/AWS, ~500 endpoints — see [environment design](../../environment/environment-design.md))
**Severity:** High
**Status:** Closed — Confirmed True Positive

> **Note on the dataset:** This investigation was conducted against a synthetic telemetry environment I designed and generated myself (entities, benign background activity, and 10 injected attack scenarios across Windows event logs, Entra ID sign-in/audit logs, email security, network, and cloud audit sources) to practice realistic SOC triage and detection engineering in Azure Data Explorer. No real organizations, individuals, or data were involved.

---

## 1. Alert Summary

| Field | Detail |
|---|---|
| **Source** | Microsoft Entra ID Identity Protection |
| **Alert Type** | Risky sign-in — "Atypical travel" |
| **Detected** | 2026-08-05 09:43 UTC |
| **Affected Identity** | gregory.ortiz@contosomeridian.com |
| **Risk Level** | High |
| **Initial Signal** | Successful sign-in to Office 365 Exchange Online from an unrecognized location, flagged high-risk, completed with single-factor authentication on an unmanaged device |

The alert on its own only indicated a risky sign-in. Triage required reconstructing what happened before and after it to determine scope and impact.

## 2. Investigation Timeline

| Time (UTC) | Event | Source Table |
|---|---|---|
| 09:12 | Gregory Ortiz receives an email from `billing@vendorcorp-payments.com` (spoofed vendor), subject referencing an urgent invoice, containing link `hxxps://secure-o365-verify[.]com/login`. Message failed SPF, DKIM, and DMARC. | `EmailEvents` |
| 09:18 | Gregory visits the phishing URL from his corporate workstation. | `ProxyLogs` |
| 09:43 | Successful sign-in to Exchange Online from IP `103.45.67.12` (Lagos, NG) — unmanaged device, single-factor auth, flagged high risk by Identity Protection. **← Alert fired here.** | `AADSignInLogs` |
| ~09:43–12:53 | *(Investigation gap — see below)* A new inbox rule (`New-InboxRule`) is created on Gregory's mailbox. | `AADAuditLogs` |
| 12:53 | An email is sent from Gregory's account to `ap@realvendorcorp.com` referencing "updated payment details" for the pending invoice. | `EmailEvents` |

**Root cause:** Credential phishing led directly to account compromise, followed by mailbox manipulation and an attempted wire-fraud redirect (classic BEC pattern) — not an isolated risky sign-in.

## 3. KQL Queries Used

**Step 1 — Pull the flagged sign-in and confirm risk context:**
```kql
AADSignInLogs
| where UserPrincipalName == "gregory.ortiz@contosomeridian.com"
| where TimeGenerated between (datetime(2026-08-05 00:00) .. datetime(2026-08-06 00:00))
| project TimeGenerated, AppDisplayName, IPAddress, Location, DeviceDetail,
          RiskLevelDuringSignIn, RiskState, AuthenticationRequirement, ResultDescription
| order by TimeGenerated asc
```

**Step 2 — Check for a preceding phishing delivery (email is almost always the entry point for an unexpected risky sign-in):**
```kql
EmailEvents
| where RecipientAddress == "gregory.ortiz@contosomeridian.com"
| where TimeGenerated between (datetime(2026-08-05 00:00) .. datetime(2026-08-05 10:00))
| project TimeGenerated, SenderAddress, Subject, URLs, SPFResult, DKIMResult, DMARCResult, ThreatType
| order by TimeGenerated asc
```

**Step 3 — Confirm the user actually interacted with the link:**
```kql
ProxyLogs
| where User == "gortiz"   // SamAccountName
| where TimeGenerated between (datetime(2026-08-05 09:00) .. datetime(2026-08-05 10:00))
| project TimeGenerated, URL, Domain, Category, Action
```

**Step 4 — Close the gap between sign-in and the fraud email (the step that changed this from "account compromise" to "active BEC"):**
```kql
AADAuditLogs
| where InitiatedBy == "gregory.ortiz@contosomeridian.com"
| where TimeGenerated between (datetime(2026-08-05 09:43) .. datetime(2026-08-05 13:00))
| project TimeGenerated, OperationName, TargetResources, Result
| order by TimeGenerated asc
```

**Step 5 — Scope check: was anyone else targeted from the same infrastructure?**
```kql
union AADSignInLogs, ProxyLogs, EmailEvents
| where IPAddress == "103.45.67.12"
    or SrcIP == "103.45.67.12"
    or SenderAddress == "billing@vendorcorp-payments.com"
| project TimeGenerated, UserPrincipalName, User, RecipientAddress, IPAddress, SrcIP
| order by TimeGenerated asc
```

## 4. Scope & Impact

- **Users affected:** 1 confirmed (Gregory Ortiz, Accounts Payable). Query in Step 5 run to confirm no other mailboxes were targeted by the same sender/IP.
- **Systems affected:** Cloud identity (Entra ID) and Exchange Online mailbox only — no evidence of lateral movement to on-prem systems.
- **Data/business impact:** A fraudulent payment-redirect email was sent to a real vendor contact (`ap@realvendorcorp.com`). If unactioned, this could have resulted in a wire transfer to an attacker-controlled account.
- **Control gap identified:** The sign-in completed with **single-factor authentication** despite being flagged high-risk — indicates a Conditional Access policy gap (risk-based sign-ins should be forced to MFA or blocked, not allowed through with password only).

## 5. Remediation & Recommendations

**Immediate containment:**
- [x] Revoke all active sessions for gregory.ortiz@contosomeridian.com
- [x] Force password reset
- [x] Locate and remove the malicious inbox rule created during the compromise window
- [x] Notify Finance/AP and contact the real vendor **out-of-band** (phone, not email) to confirm no payment is made against the fraudulent instructions

**Follow-up / hardening:**
- [ ] Review Conditional Access policy for risk-based sign-ins — high-risk sign-ins should require MFA or be blocked outright, not permitted with single-factor auth
- [ ] Block the phishing domain (`secure-o365-verify.com`) and sender domain (`vendorcorp-payments.com`) at the email gateway/proxy
- [ ] Block source IP `103.45.67.12` at the perimeter and check for reuse across other alerts
- [ ] Search all mailboxes for inbox rules created in the same time window as a broader sweep, in case this campaign wasn't limited to one target

## 6. Lessons Learned

The initial Identity Protection alert only surfaced the risky sign-in — it gave no indication of *what happened after*. Treating the alert as the whole story would have missed the inbox rule, which was the actual mechanism enabling the fraud attempt. The key investigative step was checking the audit log for the hours *following* the flagged sign-in rather than stopping at "account compromised, reset password." In hindsight, checking `AADAuditLogs` for post-compromise mailbox changes should be a standard second step for any account-compromise alert, not something to reach for only after being prompted.

---

*Queries and findings documented from an ADX-based investigation against a self-generated synthetic telemetry dataset. Full environment design and dataset generation methodology available in this repo.*

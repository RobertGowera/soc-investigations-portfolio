# SOC Investigations Portfolio

A collection of end-to-end security incident investigations conducted against a **synthetic enterprise telemetry environment** I designed and generated myself, from environment/data architecture through detection, triage, and KQL-based investigation in Azure Data Explorer.

> **Why synthetic data?** This lets me demonstrate the full lifecycle of detection engineering and SOC analysis - building the environment, generating realistic multi-source telemetry with injected attack scenarios and then investigating those scenarios "blind" (without ground truth) without touching any real organization's data.

## What's in this repo

| Folder | Contents |
|---|---|
| [`environment/`](environment/environment-design.md) | Full design of the synthetic enterprise: users, hosts, network segments, telemetry sources/schemas, the 10 injected attack scenarios, benign noise model, and dataset generation architecture |
| [`incidents/`](incidents/) | Individual incident write-ups, each includes the alert, investigation timeline, KQL queries used, scope/impact assessment, and remediation recommendations |
| [`docs/methodology.md`](docs/methodology.md) | My general approach to triage and investigation |

## Skills demonstrated

- KQL query writing against multi-source security telemetry (identity, email, endpoint, network, cloud audit logs)
- Incident triage and scoping (single alert → full attack timeline)
- Cross-source correlation (identity ↔ endpoint ↔ email ↔ network)
- Detection engineering / synthetic dataset design (MITRE ATT&CK-mapped scenarios)
- Incident documentation and remediation recommendations

## Incidents Log

| ID | Type | Severity | Status |
|---|---|---|---|
| [INC-2026-4471](incidents/INC-2026-4471-bec-phishing/) | Business Email Compromise via Credential Phishing | High | Closed — True Positive |
| *more coming* | | | |

## Environment Overview

The synthetic environment ("Contoso Meridian") models a ~500-person financial services company with hybrid Azure AD/AWS infrastructure, generating telemetry across 13 sources (Windows event logs, Entra ID sign-in/audit logs, EDR, firewall/proxy/DNS, email security, Azure/AWS cloud audit logs, M365 audit logs, VPN logs) over a 30-day period, with 10 realistic attack scenarios injected into a much larger volume of benign background activity. Full details in [environment-design.md](environment/environment-design.md).

---

*All data in this repository is synthetic. No real individuals, organizations, or systems are represented.*

# Threat Hunt Report: Lateral Movement via RDP Following Initial Access

**Hunt type:** Hypothesis-driven, structured (TaHiTI-aligned)
**Date:** June 2026
**Analyst:** Liberty Mubhau
**Scope:** Simulated MSSP client environment (generalized — no client-identifying data)

## 1. Hypothesis

> "If an attacker gains initial access to a low-privilege endpoint, they will attempt lateral movement via RDP to reach higher-value hosts (domain controllers, file servers, finance workstations) before deploying ransomware or exfiltrating data."

This hypothesis is grounded in current threat intelligence: RDP-based lateral movement remains one of the top three techniques in human-operated ransomware intrusions (consistent with Microsoft Digital Defense Report and CrowdStrike Global Threat Report findings on breakout time and lateral movement patterns).

## 2. Scoping

- **ATT&CK techniques covered:** T1021.001 (Remote Services: RDP), T1078 (Valid Accounts)
- **Data sources:** `DeviceLogonEvents`, `DeviceNetworkEvents` (Defender for Endpoint / Sentinel)
- **Time window:** Rolling 14 days
- **Out of scope:** RDP from documented jump hosts / bastion servers (excluded via asset watchlist)

## 3. Hunt Query

```kql
let JumpHosts = dynamic(["JUMP-HOST-01", "BASTION-01"]); // populate from client CMDB
DeviceLogonEvents
| where TimeGenerated > ago(14d)
| where LogonType == "RemoteInteractive"
| where DeviceName !in (JumpHosts)
| project TimeGenerated, DeviceName, AccountName, RemoteIP, ActionType
| join kind=inner (
    DeviceLogonEvents
    | where TimeGenerated > ago(14d)
    | where LogonType == "RemoteInteractive"
    | project TimeGenerated, DeviceName, AccountName
) on AccountName
| where DeviceName != DeviceName1
| where TimeGenerated1 - TimeGenerated between (0min .. 30min)
| summarize HopCount = dcount(DeviceName1), HopsInWindow = make_set(DeviceName1, 10) by AccountName, bin(TimeGenerated, 1h)
| where HopCount >= 3
| order by HopCount desc
```

*Query identifies accounts authenticating interactively to 3+ distinct hosts within a rolling 1-hour window — a pattern consistent with manual or scripted lateral movement rather than normal user behavior.*

## 4. Findings (simulated hunt output — illustrative)

| Account | Hop Count | Hosts (sample) | Assessment |
|---|---|---|---|
| `contractor.jsmith` | 4 | WKS-0231 → FILE-SRV-02 → WKS-0455 → DC-01 | Escalated — no documented reason for contractor account to reach DC-01 |
| `svc-backup` | 5 | Backup infrastructure only | Benign — confirmed against documented backup job schedule |

## 5. Recommendation

1. Convert the hunt query into a standing scheduled analytics rule with a tuned hop-count threshold (validated against 30 days of baseline before enabling auto-escalation).
2. Recommend the client implement **RDP restriction via Conditional Access / firewall segmentation** — most flagged lateral movement in this hunt was technically possible only because RDP was unrestricted between workstation VLANs and server VLANs.
3. Cross-reference flagged accounts against Privileged Identity Management (PIM) eligibility — contractor accounts reaching domain controllers is a standing-privilege problem, not just a detection gap.

## 6. Outcome

Hunt converted into Detection #4 in this portfolio (`Anomalous Service Account Interactive Logon`) after generalizing the pattern beyond the initial contractor-account finding.

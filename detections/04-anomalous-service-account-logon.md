# Detection: Anomalous Interactive Logon by Service Account

**MITRE ATT&CK:** T1078.002 – Valid Accounts: Domain Accounts / T1550 – Use Alternate Authentication Material
**Data source:** Microsoft Entra ID Identity Logs (`IdentityLogonEvents`) / Windows Security Event Logs via Sentinel
**Severity:** High

## Rationale

Service accounts are provisioned for non-interactive, automated tasks and should never authenticate via interactive logon types (Type 2 / Type 10 RDP). An interactive logon from a service account is a strong indicator of either credential misuse by an insider or lateral movement by an external attacker who has harvested service account credentials — often from misconfigured Group Policy, LAPS gaps, or Kerberoasting.

## KQL Query

```kql
let ServiceAccountPattern = @"^(svc[-_]|sa[-_]|app[-_]|sql[-_])"; // adjust to match client naming convention
DeviceLogonEvents
| where TimeGenerated > ago(1d)
| where AccountName matches regex ServiceAccountPattern
| where LogonType in ("Interactive", "RemoteInteractive") // excludes Network, Batch, Service logon types
| project TimeGenerated, DeviceName, AccountName, AccountDomain, LogonType, RemoteIP, ActionType
| order by TimeGenerated desc
```

## Companion Query: Service Accounts With Excessive Distinct Host Logons

```kql
// Complements the above — flags service accounts authenticating to an unusually wide spread of hosts,
// a common signature of an attacker pivoting with a stolen service account credential
DeviceLogonEvents
| where TimeGenerated > ago(7d)
| where AccountName matches regex @"^(svc[-_]|sa[-_]|app[-_]|sql[-_])"
| summarize DistinctHosts = dcount(DeviceName), Hosts = make_set(DeviceName, 20) by AccountName
| where DistinctHosts > 5 // baseline threshold; tune against each account's documented purpose
| order by DistinctHosts desc
```

## False Positive Analysis

- Requires an accurate, maintained **service account naming convention or watchlist** — without it, this detection either misses non-conforming accounts or over-alerts on legitimately-named human accounts. This is the single biggest tuning dependency; flag it explicitly to the client during onboarding.
- Some legitimate break-glass or admin troubleshooting scenarios involve intentional interactive logon with a service account — these should be documented as an approved exception list with time-boxed change tickets, not a blanket exclusion.

## Response Playbook

1. Confirm the account's documented purpose and normal logon pattern against CMDB/asset inventory.
2. Check for concurrent or recent Kerberoasting indicators (`Event ID 4769` with RC4 encryption) against the same account.
3. If unauthorized: force credential rotation, review the account's permission scope for least-privilege violations, and check for any scheduled tasks or services created under that identity during the incident window.
4. Recommend migrating high-privilege service accounts to Group Managed Service Accounts (gMSA) to eliminate password-based credential theft risk going forward — this is a strong consulting recommendation to include in the client report.

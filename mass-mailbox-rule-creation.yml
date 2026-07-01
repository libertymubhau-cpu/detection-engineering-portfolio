# Detection: Mass Mailbox Rule Creation (Business Email Compromise Indicator)

**MITRE ATT&CK:** T1114.003 – Email Collection: Email Forwarding Rule
**Data source:** Microsoft 365 Unified Audit Log (`OfficeActivity`) via Microsoft Sentinel
**Severity:** High

## Rationale

Attackers who gain access to a mailbox (via phishing, password spray, or session hijack) commonly create inbox rules to auto-forward or hide finance/HR-related emails — a classic Business Email Compromise (BEC) precursor to invoice fraud. Legitimate users create forwarding rules too, so the detection needs to focus on *suspicious rule characteristics*, not just rule creation itself.

## KQL Query

```kql
OfficeActivity
| where TimeGenerated > ago(1d)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| extend RuleParams = parse_json(Parameters)
| extend RuleName = tostring(RuleParams[0].Value) // rule name if present in first param, adjust per schema
| extend ForwardTo = extract(@'ForwardTo\":\[(.*?)\]', 1, tostring(Parameters))
| extend DeleteMessage = Parameters has "DeleteMessage" and Parameters has "True"
| extend MarkAsRead = Parameters has "MarkAsRead" and Parameters has "True"
| extend SuspiciousKeywordMatch = Parameters has_any ("invoice", "payment", "wire", "bank", "password", "confidential")
| where isnotempty(ForwardTo) or DeleteMessage or SuspiciousKeywordMatch
| project TimeGenerated, UserId, ClientIP, Operation, ForwardTo, DeleteMessage, MarkAsRead, SuspiciousKeywordMatch, Parameters
| order by TimeGenerated desc
```

## False Positive Analysis

- **Legitimate delegation / assistant forwarding** — executives forwarding to an EA's mailbox is common; maintain a watchlist of approved forwarding pairs (user → delegate) to suppress known-good relationships.
- **External forwarding to personal accounts** for out-of-office coverage happens, but combined with `DeleteMessage=True` or keyword matches, the risk profile changes sharply — weight these signals rather than treating any single one as sufficient for auto-escalation.
- Tune the keyword list per client — finance-heavy clients need broader financial terms; healthcare clients should include PHI-related terms.

## Response Playbook

1. Identify the forwarding destination — internal, external-but-known, or unknown external domain.
2. If external and unknown: treat as confirmed BEC staging, disable the account, and revoke sessions/tokens immediately.
3. Search `OfficeActivity` for `MailItemsAccessed` and `Send` operations in the same session to determine if data was already exfiltrated or fraudulent emails already sent.
4. Notify the client's finance/AP team proactively if the mailbox belongs to anyone with invoice or payment authority — BEC often has a live financial-loss window measured in hours.
5. Remove the malicious rule, reset credentials, and enforce MFA re-registration.

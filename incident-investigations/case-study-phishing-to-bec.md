# Incident Investigation: Phishing → Business Email Compromise (Anonymized Case Study)

**Classification:** Confirmed BEC attempt, contained pre-fraud
**Client sector:** Professional services (anonymized)
**Detection source:** Custom analytics rule (Detection #2 in this portfolio, generalized from this case)
**MITRE ATT&CK chain:** T1566.002 (Phishing: Spearphishing Link) → T1078 (Valid Accounts) → T1114.003 (Email Collection: Forwarding Rule)

> Note: All identifying details (usernames, domains, IPs, dates) have been altered or generalized. This write-up follows the actual investigation methodology and timeline structure of a real case I worked, without disclosing client-confidential information.

## Timeline

| Time (relative) | Event |
|---|---|
| T+0:00 | User receives spearphishing email impersonating a known vendor invoice portal |
| T+0:12 | User clicks link, enters credentials on a spoofed Microsoft 365 login page |
| T+0:15 | Attacker authenticates from unfamiliar ASN (VPS hosting provider, not residential/mobile) |
| T+0:18 | Attacker creates inbox rule: forwards all mail containing "invoice," "payment," "remittance" to an external address, and marks matching mail as read |
| T+2:41 | Analytics rule fires: suspicious mailbox rule creation with financial keyword match |
| T+2:47 | SOC analyst (me) begins triage |

## Triage & Investigation

1. **Confirmed the alert.** Pulled the `OfficeActivity` record for the `New-InboxRule` operation; confirmed `ForwardTo` pointed to an external domain never previously seen for this tenant.
2. **Checked sign-in context.** Cross-referenced `SigninLogs` for the same UPN in the prior 4 hours — found a successful sign-in from an unfamiliar country and ASN, with no corresponding travel or VPN usage on file for the user.
3. **Assessed MFA status.** The tenant had MFA enabled, but the user had approved a push notification — consistent with either MFA fatigue or a real-time phishing proxy (adversary-in-the-middle) capturing the session token at time of login.
4. **Scoped the blast radius.** Searched `OfficeActivity` for `Send`, `MailItemsAccessed`, and `FileAccessed` operations from the same session — no outbound fraudulent emails had been sent yet; the attacker was still in the reconnaissance/staging phase.
5. **Checked for lateral indicators.** No evidence of OAuth app consent grants or additional account compromise — contained to the single mailbox.

## Containment & Remediation

1. Disabled the compromised account and revoked all refresh tokens (killing the active session immediately).
2. Removed the malicious inbox rule.
3. Forced password reset and MFA re-registration.
4. Notified the client's finance team proactively — even though no fraudulent email had been sent yet, any inbound invoice correspondence during the exposure window needed manual verification before payment.
5. Reviewed sign-in logs tenant-wide for the same source ASN/IP to rule out a broader campaign against other users — none found.

## Root Cause & Recommendations

- **Root cause:** Credential phishing via a convincing vendor-impersonation page, likely combined with an adversary-in-the-middle proxy given the MFA push approval — the user didn't "ignore" MFA, the token was likely captured in real time.
- **Recommendation 1:** Move from push-based MFA to number-matching or phishing-resistant MFA (FIDO2/passkeys) for finance-adjacent roles — push fatigue and AiTM proxies both defeat simple push approval.
- **Recommendation 2:** Deploy Conditional Access policies restricting sign-in to expected countries/ASNs for this user population, reducing the viable attack window even after credential theft.
- **Recommendation 3:** This case directly informed Detection #2 (mass mailbox rule creation) in this portfolio — turning a one-off manual investigation into a standing detection so future instances alert in minutes, not the ~2h41m it took here before the rule fired (which itself became the justification for building a faster, more targeted version of the detection).

## Reflection

This case is the clearest example from my SOC work of the gap between *responding well* to an alert and *engineering* the detection that should have caught it faster. The manual investigation took under 10 minutes once triaged — but the rule that eventually caught it wasn't tuned for financial-keyword + forwarding-rule correlation at the time, which is why I built Detection #2 the way I did.

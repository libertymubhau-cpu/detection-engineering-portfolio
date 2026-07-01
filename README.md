# Detection Engineering & Threat Hunting Portfolio

**Liberty Mubhau** | SOC Analyst → Detection Engineer | SC-200, CySA+, CCNA
[LinkedIn](https://www.linkedin.com/in/ing-liberty-mubhau-77a19713) · Prague, Czech Republic · Open to remote/international contracts

## About this repo

Four years of hands-on SOC and MSSP experience across Microsoft Sentinel, Microsoft Defender XDR, Splunk, and CrowdStrike Falcon. This repository documents my transition from consuming detections to building them — custom KQL analytics rules, Sigma rules for cross-platform portability, threat hunting methodology, and an anonymized incident investigation write-up.

All queries are built against real Microsoft Sentinel / Defender XDR table schemas (`SigninLogs`, `OfficeActivity`, `DeviceProcessEvents`, `IdentityLogonEvents`, `EmailEvents`) and are safe to run in any tenant — no client data, no proprietary IOCs. Scenarios are based on common attack patterns I've triaged in production, generalized and rebuilt from scratch for this portfolio.

## Structure

| Folder | Contents |
|---|---|
| `/detections` | KQL analytics rules, each mapped to MITRE ATT&CK, with false-positive analysis and response guidance |
| `/sigma-rules` | Vendor-agnostic Sigma rules (portable to Splunk, Elastic, QRadar) for two of the detections |
| `/threat-hunting` | A structured proactive hunt report (hypothesis → query → findings → recommendation) |
| `/incident-investigations` | An anonymized end-to-end case study: phishing → BEC, from alert to remediation |

## Why this matters

Most SOC analysts consume detections built by someone else. This repo is proof I can go the other direction — take a threat scenario, map it to ATT&CK, write the detection logic, tune it against false positives, and hand off a response playbook. That's the job description for Detection Engineer and Sentinel Consultant roles, not SOC Analyst roles.

## Roadmap

- [ ] Add Defender XDR Advanced Hunting queries (KQL variant for `DeviceEvents`, `CloudAppEvents`)
- [ ] Add a Logic App / Sentinel Playbook (SOAR automation) for one detection
- [ ] Add a detection-as-code CI/CD example (GitHub Actions deploying analytics rules via ARM/Bicep)

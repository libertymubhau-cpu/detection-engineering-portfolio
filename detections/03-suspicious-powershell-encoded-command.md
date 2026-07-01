# Detection: Suspicious Encoded PowerShell Execution

**MITRE ATT&CK:** T1059.001 – Command and Scripting Interpreter: PowerShell
**Data source:** Microsoft Defender for Endpoint (`DeviceProcessEvents`) via Defender XDR / Sentinel
**Severity:** Medium–High (severity scales with parent process and host criticality)

## Rationale

Base64-encoded PowerShell (`-EncodedCommand` / `-enc`) is a long-standing but still highly reliable signal — it's used both by legitimate admin tooling and, disproportionately, by malware droppers and living-off-the-land attackers to evade static string-based detection. The engineering value here is in the exclusion tuning, not the detection logic itself.

## KQL Query

```kql
DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-e ", "-nop", "-noni", "-w hidden", "-windowstyle hidden")
| extend ParentProcess = tolower(InitiatingProcessFileName)
| where ParentProcess !in ("services.exe", "svchost.exe") // exclude common legitimate management-tool parents; tune per environment inventory
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated desc
```

## Decoding Helper (for triage, not alerting)

```kql
// Run manually against a specific event once flagged, to decode the Base64 payload for analyst review
let EncodedPayload = "<paste captured -enc argument here>";
print DecodedCommand = base64_decode_tostring(EncodedPayload)
```

## False Positive Analysis

- **RMM and patch management tools** (e.g., ConnectWise, NinjaOne, SCCM/Intune remediation scripts) frequently use encoded PowerShell for legitimate reasons — build and maintain a parent-process/publisher-hash allowlist rather than excluding by process name alone, since that's trivially spoofable.
- **Scheduled maintenance scripts** run by legitimate service accounts should be scoped out via an account-based watchlist, reviewed quarterly.
- Do **not** exclude by command-line content matching known-benign scripts — attackers can trivially pad or reformat encoded payloads to evade static exclusions.

## Response Playbook

1. Decode the Base64 payload and review for download cradles (`IEX`, `Net.WebClient`, `Invoke-WebRequest`), obfuscation, or C2 patterns.
2. Check `DeviceNetworkEvents` for outbound connections from the same device within ±5 minutes of execution.
3. If parent process is Office (`winword.exe`, `excel.exe`) or a browser — treat as high-confidence malicious (classic macro/phishing-to-PowerShell chain) and isolate the device immediately.
4. If confirmed malicious: isolate device via Defender for Endpoint, collect investigation package, and begin host-level IOC sweep across the tenant.

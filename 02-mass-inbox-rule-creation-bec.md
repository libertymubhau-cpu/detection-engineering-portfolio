# Detection: Impossible Travel Sign-In (Identity Compromise Indicator)

**MITRE ATT&CK:** T1078 – Valid Accounts (Initial Access / Persistence)
**Data source:** Microsoft Entra ID Sign-in Logs (`SigninLogs`) via Microsoft Sentinel
**Severity:** High

## Rationale

A single account authenticating successfully from two geographically distant locations within a time window shorter than physically possible travel indicates either credential compromise or session token theft. This is one of the highest-signal, lowest-noise identity detections when tuned correctly — the main engineering challenge is suppressing false positives from VPNs, cloud proxies, and multi-region SaaS relays.

## KQL Query

```kql
let TimeWindowMinutes = 120;
let MinDistanceKm = 500;
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0 // successful sign-ins only
| extend Latitude = todouble(LocationDetails.geoCoordinates.latitude),
         Longitude = todouble(LocationDetails.geoCoordinates.longitude)
| where isnotempty(Latitude) and isnotempty(Longitude)
| project TimeGenerated, UserPrincipalName, IPAddress, Latitude, Longitude, AppDisplayName, DeviceDetail
| sort by UserPrincipalName asc, TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated), PrevLat = prev(Latitude), PrevLon = prev(Longitude),
         PrevUser = prev(UserPrincipalName), PrevIP = prev(IPAddress)
| where UserPrincipalName == PrevUser
| extend TimeDiffMinutes = datetime_diff('minute', TimeGenerated, PrevTime)
| extend DistanceKm = geo_distance_2points(Longitude, Latitude, PrevLon, PrevLat) / 1000
| where TimeDiffMinutes between (0 .. TimeWindowMinutes) and DistanceKm > MinDistanceKm
| extend ImpliedSpeedKmh = DistanceKm / (TimeDiffMinutes / 60.0)
| where ImpliedSpeedKmh > 900 // faster than commercial flight
| project TimeGenerated, UserPrincipalName, PrevIP, IPAddress, DistanceKm, TimeDiffMinutes, ImpliedSpeedKmh, AppDisplayName
| order by ImpliedSpeedKmh desc
```

## False Positive Analysis

- **Corporate VPN egress / SASE providers** (Zscaler, Netskope) can create apparent location jumps — maintain a watchlist of known corporate egress IP ranges and exclude them before alerting.
- **Shared service accounts** used by multi-region automation should be excluded via a watchlist or moved to a separate lower-severity rule.
- **Mobile carrier NAT reassignment** occasionally produces short-distance false positives; the 900 km/h speed threshold (above commercial flight speed) filters most of these out.

## Response Playbook

1. Confirm both sign-ins against the same session/token, not two independent valid logins from a traveling user.
2. Check for MFA on both sign-ins — if the second sign-in bypassed MFA (token replay), treat as confirmed compromise.
3. Disable the account and revoke all refresh tokens immediately (`Revoke-AzureADUserAllRefreshToken` or Entra ID portal equivalent).
4. Pivot to `OfficeActivity` and `CloudAppEvents` for the same UPN to check for mailbox rule creation, OAuth app consent, or data exfiltration in the session window.
5. Escalate to client infosec team per severity SLA; open ticket with full sign-in timeline attached.

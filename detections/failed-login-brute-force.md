# Detection: Failed Login / Brute Force

## Overview
Detects repeated failed authentication attempts against a local account within 
a 5-minute window, simulating a brute-force attack pattern.

## Event ID
`4625` – An account failed to log on

## KQL Query
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| project TimeGenerated, Account, IpAddress, FailedAttempts
| sort by FailedAttempts desc
```

## Query Explanation
- Filters for Event ID 4625 (failed logon events)
- Groups results by account and IP in 5-minute buckets
- Triggers when 5 or more failures occur within that window
- Returns account name, source IP, and failure count for triage

## Analytics Rule Configuration
| Setting | Value |
|---|---|
| Rule Name | Brute Force – Failed Login Threshold |
| Severity | Medium |
| Query Frequency | Every 5 minutes |
| Lookup Period | Last 5 minutes |
| Alert Threshold | Results > 0 |
| Entity Mapping | Account, IP Address |

## MITRE ATT&CK Mapping
| Field | Value |
|---|---|
| Tactic | Credential Access |
| Technique | T1110 – Brute Force |
| Sub-technique | T1110.001 – Password Guessing |

## Screenshots
![Alert Firing and other related screenshots]
(../Screenshots/failed-login-alert-1.png)
(../Screenshots/failed-login-resolved.png)

## Findings
Simulated 10 consecutive failed login attempts within 60 seconds. Alert triggered 
after the 5th failure within the 5-minute window. Sentinel created an incident 
automatically and mapped the source account and IP for investigation.

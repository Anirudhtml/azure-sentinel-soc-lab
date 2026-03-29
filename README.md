# 🛡️ Azure Sentinel SOC Lab

> A hands-on Security Operations Center (SOC) lab built on Microsoft Azure, 
> simulating real-world threat detection, alert triage, and incident investigation 
> using Microsoft Sentinel and KQL.

---

## 📐 Lab Architecture

| Component | Details |
|---|---|
| Virtual Machine | Windows 11 (Azure-hosted) |
| Log Ingestion | Azure Monitor Agent → Log Analytics Workspace |
| SIEM | Microsoft Sentinel |
| Detection Language | Kusto Query Language (KQL) |
| Framework | MITRE ATT&CK |

---

## 🔍 Detections Implemented

### 1. Brute Force / Failed Login Attempts

Detects repeated failed authentication events against a local account within a short window — simulating a brute-force attack pattern.

**Event ID:** `4625` – An account failed to log on
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| project TimeGenerated, Account, IpAddress, FailedAttempts
| sort by FailedAttempts desc
```

**MITRE ATT&CK Mapping:**
- Tactic: Credential Access
- T1110 – Brute Force

---

### 2. Account Enumeration / Reconnaissance

Detects execution of common enumeration commands used by attackers to map out users, groups, and system privileges after initial access.

**Monitored Commands:** `whoami`, `net user`, `net group`, `net localgroup`
```kql
SecurityEvent
| where EventID == 4688
| where CommandLine has_any ("whoami", "net user", "net group", "net localgroup")
| project TimeGenerated, Account, Computer, CommandLine, ParentProcessName
| sort by TimeGenerated desc
```

**MITRE ATT&CK Mapping:**
- Tactic: Discovery
- T1087 – Account Discovery
- T1069 – Permission Groups Discovery

---

### 3. Suspicious Command Execution (PowerShell / CMD)

Detects spawning of PowerShell or CMD processes, particularly from unusual parent processes, which may indicate malicious script execution or living-off-the-land behavior.
```kql
SecurityEvent
| where EventID == 4688
| where Process has_any ("powershell.exe", "cmd.exe")
| where ParentProcessName !in ("explorer.exe", "services.exe")
| project TimeGenerated, Account, Computer, Process, ParentProcessName, CommandLine
| sort by TimeGenerated desc
```

**MITRE ATT&CK Mapping:**
- Tactic: Execution
- T1059 – Command and Scripting Interpreter
- T1059.001 – PowerShell
- T1059.003 – Windows Command Shell

---

## 🧪 Simulated Incident Walkthrough

1. **Attack Simulation** — Manually triggered 10 failed login attempts within 60 seconds and executed enumeration commands via CMD.
2. **Alert Triggered** — Sentinel analytics rules fired within ~90 seconds of threshold being crossed.
3. **Triage** — Reviewed incident details: affected account, source IP, timeline of events, and associated process tree.
4. **Investigation** — Correlated failed logins with subsequent enumeration commands to identify a plausible attack chain (Credential Access → Discovery).
5. **Documentation** — Produced a structured incident summary including affected assets, timeline, MITRE mapping, and recommended containment steps.

---

## 🧠 Skills Demonstrated

- **Detection Engineering** — Authored custom KQL analytics rules with thresholds and field filtering
- **SIEM Operations** — Configured Microsoft Sentinel workbooks, analytics rules, and incident queues
- **Log Analysis** — Queried and interpreted Windows Security Event logs via Log Analytics Workspace
- **MITRE ATT&CK Mapping** — Mapped detections to relevant tactics and techniques
- **Incident Triage & Reporting** — Investigated simulated incidents and produced structured findings

---

## 📸 Screenshots

| Description | Preview |
|---|---|
| Sentinel Incident Queue | *(add screenshot)* |
| KQL Query – Failed Logins | *(add screenshot)* |
| Analytics Rule Configuration | *(add screenshot)* |
| Incident Timeline View | *(add screenshot)* |

---

## 🚀 Key Outcomes

- Detected simulated brute-force and reconnaissance activity with custom KQL rules
- Reduced mean time to detect (MTTD) to under 2 minutes for threshold-based alerts
- Produced incident reports aligned to MITRE ATT&CK, mirroring real SOC workflows
- Demonstrated end-to-end SOC pipeline: log ingestion → detection → triage → documentation

---

## 🔗 Related Certifications & Learning

- CompTIA Security+ ✅
- Microsoft SC-200 (Security Operations Analyst) — In Progress
- TryHackMe SOC L1 Learning Path — In Progress

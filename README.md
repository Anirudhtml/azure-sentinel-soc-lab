# 🛡️ Azure Sentinel SOC Lab

Built a hands-on SOC lab using Microsoft Sentinel to detect and analyze suspicious activities on a Windows virtual machine.

---

## Lab Architecture
- Azure Virtual Machine (Windows 11)
- Log ingestion via Azure Monitor Agent
- Microsoft Sentinel as SIEM
- KQL used for detection logic

---

## Detections Implemented

### 1. Failed Login Attempts
- Detects multiple failed login attempts (Event ID 4625)
- Simulates brute-force behavior

---

### 2. Account Enumeration Activity
- Detects commands like `whoami`, `net user`, `net group`
- Identifies reconnaissance behavior

**MITRE ATT&CK Mapping:**
- Tactic: Discovery
- T1087 – Account Discovery
- T1069 – Permission Groups Discovery

---

### 3. Suspicious Command Execution
- Detects execution of PowerShell and CMD processes
- Identifies potential malicious command execution

**MITRE ATT&CK Mapping:**
- Tactic: Execution
- T1059 – Command and Scripting Interpreter

---

## 🧠 Skills Demonstrated

- SIEM: Microsoft Sentinel
- Log Analysis using KQL
- Threat Detection & Analysis
- Incident Investigation & Reporting
- MITRE ATT&CK Mapping

---

## 📸 Screenshots

### 🖥️ VM Setup
![VM Setup]

---

### 🔍 Log Analysis (KQL Query Results)
![Log Query]

---

### 🚨 Detection & Alert Triggered
![Alert]

---

### 🧾 Incident Investigation & Resolution
![Resolved Case]

---

## 🧩 Project Overview

This project simulates real-world SOC operations by:
- Generating logs from a Windows VM
- Creating detection rules in Microsoft Sentinel
- Investigating alerts and documenting findings

---

## 🚀 Outcome

This lab demonstrates practical SOC skills including detection engineering, alert triage, and incident reporting.

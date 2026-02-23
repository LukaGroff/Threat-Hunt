# Cyber Range Threat Hunt - The BROKER (Hard)

<img width="600" height="800" alt="image" src="https://github.com/user-attachments/assets/952f6aab-a147-4359-8e05-f13aba29c986" />


**Date of Incident:** 21 February 2026  
**Data Source:** Log Analytics workspaces, Microsoft Defender

**Scope:** Three Windows endpoints


**Analyst:** Luka Groff

---

# 🛡️ Incident Response Case Study  
## Ashford Sterling Recruitment – Full Attack Lifecycle Investigation

This case study documents a complete enterprise compromise — from initial infection to credential theft, lateral movement, persistence, data staging, and anti-forensics activity.

---

## 🚩 Initial Access

The attack began with a malicious payload disguised as a resume:

`Daniel_Richardson_CV.pdf.exe`

The file was executed via user interaction (`explorer.exe`), spawning a legitimate Windows process (`notepad.exe`) as part of the infection chain.

---

## 🌐 Command & Control

The malware established outbound communication to attacker-controlled infrastructure:

- **C2 Domain:** `cdn.cloud-endpoint.net`
- **Staging Domain:** `sync.cloud-endpoint.net`

C2 traffic originated from the initial payload process.

---

## 🔐 Credential Access

The attacker targeted local credential stores:

- Registry hives accessed: `SAM`, `SYSTEM`
- Execution identity: `Sophie.Turner`
- Data staged locally under: `C:\Users\Public\`

Reflective loading activity was detected via:

`ActionType: ClrUnbackedModuleLoaded`

The in-memory credential theft tool identified was:

**SharpChrome**

The malicious assembly was injected into:

`notepad.exe`

---

## 🧭 Discovery & Enumeration

Post-compromise reconnaissance included:

- `whoami`
- `net view`
- `net localgroup administrators`

The attacker mapped user context, network shares, and local privilege groups.

---

## 🔁 Persistence Mechanisms

Multiple persistence techniques were deployed:

- Remote access tool: **AnyDesk**
- Scheduled task: `MicrosoftEdgeUpdateCheck`
- Renamed payload: `RuntimeBroker.exe`
- Backdoor account created: `svc_backup`

Unattended access was configured with a set password, ensuring continued control.

---

## 🔀 Lateral Movement

The attacker moved through the environment using:

- Failed attempts: `WMIC.exe`, `PsExec.exe`
- Successful pivot: `mstsc.exe` (RDP)

Movement path:

`as-pc1 > as-pc2 > as-srv`

Authenticated user:

`david.mitchell`

A previously disabled account was reactivated (`active:yes`) to maintain access.

---

## 📂 Data Access & Staging

Sensitive financial data was accessed and modified:

`BACS_Payments_Dec2025.ods`

Evidence of editing was confirmed via lock artifact:

`.~lock.BACS_Payments_Dec2025.ods#`

Data was archived for potential exfiltration:

`Shares.7z`

---

## 🧹 Anti-Forensics

To cover their tracks, the attacker:

- Cleared `Security` and `System` logs
- Loaded malicious .NET assemblies reflectively
- Injected tooling directly into memory

---

## 🎯 Skills Demonstrated

- Advanced Microsoft Defender for Endpoint hunting
- Process injection detection
- Reflective loading analysis
- Registry hive credential targeting
- Lateral movement reconstruction
- Persistence mapping
- Data staging and exfiltration analysis
- MITRE ATT&CK technique alignment

---

This investigation reconstructs the full attack lifecycle using behavioral telemetry and advanced hunting queries, demonstrating end-to-end incident response and threat hunting capability.


---

## SECTION 1: INITIAL ACCESS [Moderate]

---

### FLAG 1 – Initial Infection Vector
**Finding:** The infection chain began with execution of a malicious file masquerading as a PDF resume. The double-extension executable initiated the compromise and triggered subsequent malicious process activity.

**File Identified:**
```
Daniel_Richardson_CV.pdf.exe
```

**MITRE:** T1204.002 – User Execution: Malicious File

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "as-pc"
| where AccountName contains "sophie"
| where InitiatingProcessParentId == "4268"
| project
    TimeGenerated,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    FolderPath,
    InitiatingProcessParentId
| order by TimeGenerated asc
```
**Alert**: an alert was triggered, "Suspicious executable with multiple file extensions", which clearly shows Daniel_Richardson_CV.pdf.exe
was the root cause of the infection.

<img width="400" height="1012" alt="image" src="https://github.com/user-attachments/assets/ccd5aeeb-11e2-4ef1-8984-081d13896e96" />

**Logs**

<img width="900" height="784" alt="image" src="https://github.com/user-attachments/assets/ec023980-10e1-4f72-984e-825825719b4e" />

<img width="900" height="790" alt="image" src="https://github.com/user-attachments/assets/4ad4ab8e-faaa-46fc-873e-54edf407509b" />

As can be seen from the logs, Daniel_Richardson_CV.pdf.exe was responsible for several malicious activities, which answer many questions.

---

### FLAG 2 – Initial Payload Hash
**Finding:** The malicious executable responsible for the initial compromise was uniquely identified via its SHA256 hash, enabling precise tracking across telemetry and preventing reliance on filename-based detection alone.

**SHA256 Identified:**
```
48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5
```

**MITRE:** T1021 – Remote Services

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "as-pc"
| where AccountName contains "sophie"
| where InitiatingProcessCommandLine contains "Daniel_Richardson_CV.pdf.exe"
| project InitiatingProcessSHA256
```

---

### FLAG 3 – User Execution Context
**Finding:** The malicious payload was launched via direct user interaction. Process lineage analysis revealed that the executable was initiated by the Windows shell, confirming manual execution rather than automated exploitation.

**Parent Process Identified:**
```
explorer.exe
```

**MITRE:** T1204 – User Execution

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "as-pc"
| where AccountName contains "sophie"
| where InitiatingProcessCommandLine contains "Daniel_Richardson_CV.pdf.exe"
| project
    TimeGenerated,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName
| order by TimeGenerated asc
```

<img width="500" height="674" alt="image" src="https://github.com/user-attachments/assets/a33bfa3b-12aa-4154-8873-cb2532d3882c" />

---

### FLAG 4 – Suspicious Child Process Spawn
**Finding:** Following execution, the malicious payload spawned a legitimate Windows process to blend into normal system activity. This behavior indicates potential process injection or execution staging within a trusted binary.

**Child Process Identified:**
```
notepad.exe
```

**MITRE:** T1055 – Process Injection

notepad.exe can be seen as the last child process of the Daniel_Richardson_CV.pdf.exe, which was later confirmed to be a process injection.

---

### FLAG 5 – Suspicious Process Arguments
**Finding:** The spawned legitimate process executed with abnormal arguments, indicating it was not opened for normal user interaction but instead likely used as a host process for malicious activity.

**Full Command Line Observed:**
```
notepad.exe ""
```

**MITRE:** T1055 – Process Injection

---

## SECTION 2: COMMAND & CONTROL [Moderate]

---

### FLAG 6 – Command & Control Domain
**Finding:** The compromised host established outbound communication to attacker-controlled infrastructure, confirming active command and control (C2) operations following initial execution.

**C2 Domain Identified:**
```
cdn.cloud-endpoint.net
```

**MITRE:** T1071.001 – Application Layer Protocol: Web Protocols

**KQL:**
```kql
DeviceNetworkEvents
| where DeviceName contains "as-pc1"
| where InitiatingProcessAccountName contains "sophie"
| where InitiatingProcessFileName contains "Daniel_Richardson"
| project TimeGenerated, AdditionalFields, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, RemoteIP, RemoteUrl
| sort by TimeGenerated asc 
```

<img width="900" height="394" alt="image" src="https://github.com/user-attachments/assets/5abbea1f-365f-43ad-a38f-184075fe2705" />

---

### FLAG 7 – C2 Process Attribution
**Finding:** Telemetry confirmed that the original malicious payload process was responsible for initiating outbound command-and-control traffic, linking network activity directly to the infection source.

**Process Identified:**
```
daniel_richardson_cv.pdf.exe
```

**MITRE:** T1071.001 – Application Layer Protocol: Web Protocols

---

### FLAG 8 – Payload Staging Infrastructure
**Finding:** In addition to command-and-control communication, the attacker leveraged a separate external domain to host and retrieve additional payloads, indicating staged infrastructure supporting the intrusion.

**Staging Domain Identified:**
```
sync.cloud-endpoint.net
```

**MITRE:** T1105 – Ingress Tool Transfer

**KQL:**
```kql
DeviceNetworkEvents
| where DeviceName contains "as-pc"
| where InitiatingProcessAccountName contains "sophie" or InitiatingProcessAccountName contains "david"
| where RemoteUrl != ""
| project TimeGenerated, AdditionalFields, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, RemoteIP, RemoteUrl
| sort by TimeGenerated asc 
```

<img width="800" height="338" alt="image" src="https://github.com/user-attachments/assets/07b66f3d-4876-4866-95ac-c5fa7b98ac84" />

The attacker used the built-in Windows utility certutil.exe to download the malicious payload from the external staging domain (sync.cloud-endpoint.net) and saved it locally as RuntimeBroker.exe in C:\Users\Public\. This demonstrates tool transfer via a living-off-the-land binary and renaming of the payload for evasion and persistence.

---

## SECTION 3: CREDENTIAL ACCESS [Hard]

---

### FLAG 9 – Registry Hive Credential Targeting
**Finding:** The attacker accessed sensitive local registry hives containing credential material. Specifically, the Security Account Manager (SAM) and SYSTEM hives were targeted to enable offline password hash extraction.

**Registry Hives Identified:**
```
sam, system
```

**MITRE:** T1003.002 – OS Credential Dumping: Security Account Manager

**Alerts**

<img width="600" height="276" alt="image" src="https://github.com/user-attachments/assets/86ae2f8b-40b4-4364-ab98-dfc07145d948" />

<img width="600" height="176" alt="image" src="https://github.com/user-attachments/assets/c2c6ba5a-6456-4840-beb8-14faba951438" />

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "as-pc"
| where AccountName contains "sophie"
| where ProcessCommandLine contains "HKLM"
| project
    TimeGenerated,
    ActionType,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessCommandLine
| order by TimeGenerated asc
```

<img width="800" height="190" alt="image" src="https://github.com/user-attachments/assets/55a8fd53-a814-4d62-9bd6-aa8e2acde181" />

---

### FLAG 10 – Local Credential Staging Location
**Finding:** Extracted credential data was written to a publicly accessible directory prior to potential exfiltration. This staging step allowed the attacker to consolidate harvested registry hive data before transferring it externally.

**Staging Directory Identified:**
```
C:\Users\Public\
```

**MITRE:** T1074.001 – Data Staged: Local Data Staging

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "sys1-dept"
| project TimeGenerated, InitiatingProcessRemoteSessionDeviceName, ProcessRemoteSessionDeviceName, ProcessRemoteSessionIP, ProcessCommandLine
| where ProcessRemoteSessionDeviceName != ""
| order by TimeGenerated asc
```

<img width="1000" height="578" alt="image" src="https://github.com/user-attachments/assets/7f062d7a-b598-4489-99c8-4f839c32e662" />

---

### FLAG 11 – Bonus Matrix Activity by a New Remote Session Context
**Finding:** Another remote session device associated with HR functions accessed bonus payout-related artifacts later in the chain.

**Remote Session Department:**
```
YE-HRPLANNER
```

**MITRE:** T1021 – Remote Services

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "sys1-dept"
| project TimeGenerated, InitiatingProcessRemoteSessionDeviceName, ProcessRemoteSessionDeviceName, ProcessRemoteSessionIP, ProcessCommandLine
| where ProcessRemoteSessionDeviceName != ""
| order by TimeGenerated asc
```

<img width="1000" height="610" alt="image" src="https://github.com/user-attachments/assets/fc06f772-3f89-433f-acfe-744d94da88a2" />

---

### FLAG 12 – Performance Review Access Validation
**Finding:** Employee performance review files were accessed unintentionally from a separate directory using user-level tooling.

**Access Timestamp:**
```
2025-12-03T07:25:15.6288106Z
```

**MITRE:** T1083 – File and Directory Discovery

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "sys1-dept"
| project TimeGenerated, InitiatingProcessRemoteSessionDeviceName, ProcessRemoteSessionDeviceName, ProcessRemoteSessionIP, ProcessCommandLine
| where ProcessRemoteSessionDeviceName != ""
| order by TimeGenerated asc
```

<img width="700" height="290" alt="image" src="https://github.com/user-attachments/assets/25322990-9e5a-41ea-930f-7bd0b53e48b2" />

---

### FLAG 13 – Approved / Final Bonus Artifact Access
**Finding:** The finalized and approved year-end bonus file was accessed without authorization.

**Unauthorized Access Timestamp:**
```
2025-12-03T07:25:39.1653621Z
```

**MITRE:** T1005 – Data from Local System

**KQL:**
```kql
DeviceEvents
| where DeviceName contains "sys1-dept"
| where ActionType contains "SensitiveFileRead"
| where FileName contains "bonus"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessRemoteSessionDeviceName
| order by TimeGenerated asc 
```

<img width="650" height="350" alt="image" src="https://github.com/user-attachments/assets/eff7fbd1-a45e-417e-8e71-d0cc45d59944" />

---

### FLAG 14 – Candidate Archive Creation Location
**Finding:** A suspicious archive containing candidate-related materials was created in a user document directory.

**Archive Path:**
```
C:\Users\5y51-D3p7\Documents\Q4Candidate_Pack.zip
```

**MITRE:** T1074.001 – Data Staged: Local Data Staging

**KQL:**
```kql
DeviceFileEvents
| where InitiatingProcessAccountName contains "5y51-d3p7"
| where DeviceName contains "sys1-dept"
| where FileName has_any ("zip", "rar")
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessAccountName
| order by TimeGenerated asc 
```

<img width="650" height="294" alt="image" src="https://github.com/user-attachments/assets/9d2a79fa-55db-4338-9426-6833fbff6586" />

---

### FLAG 15 – Outbound Transfer Attempt Timestamp
**Finding:** A network POST-style outbound connection was attempted shortly after archive creation.

**Outbound Attempt Timestamp:**
```
2025-12-03T07:26:28.5959592Z
```

**MITRE:** T1041 – Exfiltration Over C2 Channel

**KQL:**
```kql
DeviceNetworkEvents
| where DeviceName contains "sys1-dept"
| project TimeGenerated, AdditionalFields, ActionType, RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessFileName, RemoteIP, RemotePort
| order by TimeGenerated asc 
```

*I checked for network events right after archive file creation*

<img width="600" height="400" alt="image" src="https://github.com/user-attachments/assets/02cfb869-103f-41a5-b03c-ec614c8886e7" />

---

### FLAG 16 – Local Log Clearing Attempt Evidence
**Finding:** An attempt was made to clear PowerShell operational logs to reduce forensic visibility.

**Command Used:**
```
"wevtutil.exe" cl Microsoft-Windows-PowerShell/Operational
```

**MITRE:** T1070.001 – Indicator Removal on Host: Clear Windows Event Logs

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "sys1-dept"
| project TimeGenerated, InitiatingProcessRemoteSessionDeviceName, ProcessRemoteSessionDeviceName, ProcessRemoteSessionIP, ProcessCommandLine
| where ProcessRemoteSessionDeviceName != ""
| order by TimeGenerated asc 
```

<img width="750" height="276" alt="image" src="https://github.com/user-attachments/assets/e62c1bf4-577b-4497-b5b0-753321eb0721" />

---

### FLAG 17 – Second Endpoint Scope Confirmation
**Finding:** Similar telemetry patterns confirmed a second endpoint was involved in the activity chain.

**Second Compromised Endpoint:**
```
main1-srvr
```

**MITRE:** T1082 – System Information Discovery

**KQL:**
```kql
DeviceProcessEvents
| where ProcessCommandLine contains "scorecard"
| project TimeGenerated, AccountName, FolderPath, FileName, InitiatingProcessCommandLine, InitiatingProcessFileName, ProcessCommandLine, ProcessRemoteSessionDeviceName
| where ProcessRemoteSessionDeviceName != ""
| order by TimeGenerated asc 
```

<img width="800" height="296" alt="image" src="https://github.com/user-attachments/assets/fa6771f1-f9aa-40c2-ab2e-7fa6f3dc3472" />

---

### FLAG 18 – Approved Bonus Artifact Access on Second Endpoint
**Finding:** The approved bonus artifact was accessed again on the second endpoint.

**Initiating Process Creation Time:**
```
2025-12-04T03:11:58.6027696Z
```

**MITRE:** T1005 – Data from Local System

**KQL:**
```kql
DeviceProcessEvents
| where AccountName contains "main1-srvr"
| where ProcessCommandLine contains "approved"
| project TimeGenerated, AccountName, InitiatingProcessCreationTime,FolderPath, FileName, InitiatingProcessCommandLine, InitiatingProcessFileName, ProcessCommandLine, ProcessRemoteSessionDeviceName
| order by TimeGenerated asc 
```

<img width="650" height="524" alt="image" src="https://github.com/user-attachments/assets/9984252d-e27c-4ec6-a93e-1bc520b4a1fd" />

---

### FLAG 19 – Employee Scorecard Access on Second Endpoint
**Finding:** Employee scorecard files were accessed again under a different remote session context.

**Remote Session Device:**
```
YE-FINANCEREVIE
```

**MITRE:** T1021 – Remote Services

**KQL:**
```kql
DeviceProcessEvents
| where AccountName contains "main1-srvr"
| where ProcessCommandLine contains "scorecard"
| project TimeGenerated, AccountName, InitiatingProcessCreationTime,FolderPath, FileName, InitiatingProcessCommandLine, InitiatingProcessFileName, ProcessCommandLine, ProcessRemoteSessionDeviceName
| order by TimeGenerated asc 
```

<img width="800" height="510" alt="image" src="https://github.com/user-attachments/assets/ab9c0597-8945-42de-9dc5-58fa6a055817" />

---

### FLAG 20 – Staging Directory Identification on Second Endpoint
**Finding:** A dedicated staging directory was used to consolidate internal reference materials and archives.

**Staging Path:**
```
C:\Users\Main1-Srvr\Documents\InternalReferences\ArchiveBundles\YearEnd_ReviewPackage_2025.zip
```

**MITRE:** T1074 – Data Staged

**KQL:**
```kql
DeviceFileEvents
| where InitiatingProcessAccountName contains "main1-srvr"
| where FileName has_any ("zip", "rar")
| project TimeGenerated, DeviceName, FileName, FolderPath
| order by TimeGenerated asc 
```

<img width="650" height="228" alt="image" src="https://github.com/user-attachments/assets/a8a459b1-b869-4836-9fd4-0ae5eb99ab17" />

---

### FLAG 21 – Staging Activity Timing on Second Endpoint
**Finding:** Final staging activity occurred shortly before outbound connection attempts.

**Staging Timestamp:**
```
2025-12-04T03:15:29.2597235Z
```

**MITRE:** T1074 – Data Staged

**KQL:**
```kql
DeviceFileEvents
| where InitiatingProcessAccountName contains "main1-srvr"
| where FileName has_any ("zip", "rar")
| project TimeGenerated, DeviceName, FileName, FolderPath
| order by TimeGenerated asc 
```

<img width="650" height="228" alt="image" src="https://github.com/user-attachments/assets/a8a459b1-b869-4836-9fd4-0ae5eb99ab17" />

---

### FLAG 22 – Outbound Connection Remote IP (Final Phase)
**Finding:** The second endpoint attempted an outbound connection consistent with data transfer behavior.

**Remote IP:**
```
54.83.21.156
```

**MITRE:** T1041 – Exfiltration Over C2 Channel

**KQL:**
```kql
DeviceNetworkEvents
| where DeviceName contains "main1-srvr"
| where InitiatingProcessAccountName contains "main1-srvr"
| project TimeGenerated, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated asc 
```

<img width="650" height="350" alt="image" src="https://github.com/user-attachments/assets/4505464d-87b7-4754-8ffe-ac71404e1f71" />

---

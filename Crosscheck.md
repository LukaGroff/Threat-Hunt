# Cyber Range Threat Hunt - ❌ Crosscheck

<img width="683" height="1024" alt="image" src="https://github.com/user-attachments/assets/84ab44ce-f551-4fe8-bc96-ac3827ee2048" />


**Date of Incident:** 1 December 2025  
**Data Source:** Log Analytics workspaces  
**Scope:** Two Windows endpoints


**Analyst:** Luka Groff

---

## Executive Overview
An investigation identified unauthorized activity involving misuse of a legitimate user account across two endpoints. The actor used remote access and PowerShell-based tooling to perform system reconnaissance and access sensitive HR and compensation-related files, including employee scorecards and finalized bonus documents. Persistence was established through registry and scheduled task mechanisms, and sensitive data was staged into archives. Outbound connectivity was tested and attempted, and log-clearing activity was observed, indicating intent to evade detection. While no confirmed data exfiltration occurred, the behavior demonstrates deliberate preparation for unauthorized data transfer and represents a high-risk incident with exposure of sensitive internal information.
- **What happened (finding)**
- **Why it matters (impact)**
- **MITRE ATT&CK mapping**
- **Representative KQL used to identify the activity**

---

## Attack Timeline & Key Findings

### Initial Access
- Endpoint identified: `sys1-dept`
- Account observed: `5y51-d3p7`
- Access type: `Remote session`
- Source IP: `192.168.0.110`

### Early Reconnaissance
- Support script executed:`"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\5y51-D3p7\Downloads\PayrollSupportTool.ps1`
- First recon command: `"whoami.exe" /all`

### Sensitive Data Discovery
- First bonus-related file accessed: `BonusMatrix_Draft_v3.xlsx`
- Additional sensitive artifacts observed: `Employee scorecards`, `Performance review files`, `Approved year-end bonus documents`

### Data Staging
- Staging process ID: `2533274790396713`
- Initial archive created: `C:\Users\5y51-D3p7\Documents\Q4Candidate_Pack.zip`

### Outbound Connectivity Testing
- First outbound connection attempt: `2025-12-03T06:27:31.1857946Z`
- Subsequent outbound attempt: `2025-12-03T07:26:28.5959592Z`

### Persistence
- Registry Run key modified: `HKEY_CURRENT_USER\S-1-5-21-805396643-3920266184-3816603331-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- Scheduled task created: `Task name: BonusReviewAssist`

### Cross-Department Access Indicators
- Remote session user accessing scorecards: `YE-HELPDESKTECH`
- Remote session department accessing bonus data: `YE-HRPLANNER`

### Defense Evasion
- Log clearing attempt executed: `"wevtutil.exe" cl Microsoft-Windows-PowerShell/Operational`

### Secondary Endpoint Activity
- Second endpoint identified: `main1-srvr`
- Approved bonus artifact accessed: `Process creation time: 2025-12-04T03:11:58.6027696Z`
- Employee scorecard access from remote session device: `YE-FINANCEREVIE`

### Final Staging & Exfiltration Attempt
- Final staging directory: `C:\Users\Main1-Srvr\Documents\InternalReferences\ArchiveBundles\YearEnd_ReviewPackage_2025.zip`
- Staging activity timestamp: `2025-12-04T03:15:29.2597235Z`
- Final outbound connection attempt: `Destination IP: 54.83.21.156`

---

### FLAG 1 – Initial Endpoint Association
**Finding:** A specific local account was first observed in process telemetry, allowing identification of the initial endpoint tied to the activity chain.

**Endpoint Identified:**
```
sys1-dept
```

**MITRE:** T1078 – Valid Accounts

**KQL:**
```kql
DeviceProcessEvents
| where AccountName contains "5y51-d3p7"
| project TimeGenerated, AccountName, DeviceName
| order by TimeGenerated asc 
```

<img width="800" height="462" alt="image" src="https://github.com/user-attachments/assets/9ca8698b-e09a-4ca5-960d-75894ca72a12" />

---

### FLAG 2 – Remote Session Source Attribution
**Finding:** Remote session metadata revealed the originating source IP responsible for the initial access to the first endpoint.

**Source IP:**
```
192.168.0.110
```

**MITRE:** T1021 – Remote Services

**KQL:**
```kql
DeviceNetworkEvents
| where DeviceName contains "sys1-dept"
| where InitiatingProcessRemoteSessionIP != ""
```

<img width="1000" height="640" alt="image" src="https://github.com/user-attachments/assets/8272664e-245c-4a48-a809-fc0c6019c408" />

---

### FLAG 3 – Support Script Execution Confirmation
**Finding:** A PowerShell script masquerading as a payroll support tool was executed from a user-accessible directory, indicating potential abuse of trusted tooling.

**Command Used:**
```
"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\5y51-D3p7\Downloads\PayrollSupportTool.ps1
```

**MITRE:** T1059.001 – Command and Scripting Interpreter: PowerShell

**KQL:**
```kql
DeviceProcessEvents
| where AccountName contains "5y51-d3p7"
| where DeviceName contains "sys1-dept"
| where ProcessCommandLine contains "powershell"
| project TimeGenerated, AccountName, FolderPath, FileName, InitiatingProcessCommandLine, InitiatingProcessFileName, ProcessCommandLine
| order by TimeGenerated asc 
```

<img width="800" height="392" alt="image" src="https://github.com/user-attachments/assets/c3709943-50e0-48cd-a6d2-eee115ed06e4" />

---

### FLAG 4 – System Reconnaissance Initiation
**Finding:** The attacker initiated reconnaissance to enumerate user identity and privilege context immediately after gaining execution capability.

**Recon Command:**
```
"whoami.exe" /all
```

**MITRE:** T1033 – System Owner/User Discovery

**KQL:**
```kql
DeviceProcessEvents
| where AccountName contains "5y51-d3p7"
| where DeviceName contains "sys1-dept"
| project TimeGenerated, AccountName, FolderPath, FileName, InitiatingProcessCommandLine, InitiatingProcessFileName, ProcessCommandLine
| order by TimeGenerated asc 
```

<img width="800" height="398" alt="image" src="https://github.com/user-attachments/assets/08aec7c9-6e25-4297-9cb5-147fe2f57959" />

---

### FLAG 5 – Sensitive Bonus-Related File Exposure
**Finding:** Exploratory activity led to the discovery of sensitive year-end compensation data.

**Sensitive File Identified:**
```
BonusMatrix_Draft_v3.xlsx
```

**MITRE:** T1083 – File and Directory Discovery

**KQL:**
```kql
DeviceProcessEvents
| where AccountName contains "5y51-d3p7"
| where DeviceName contains "sys1-dept"
| project TimeGenerated, AccountName, FolderPath, FileName, InitiatingProcessCommandLine, InitiatingProcessFileName, ProcessCommandLine
| order by TimeGenerated asc 
```

<img width="650" height="398" alt="image" src="https://github.com/user-attachments/assets/a125bf36-0154-44e4-8b39-b719472f12ee" />

---

### FLAG 6 – Data Staging Activity Confirmation
**Finding:** Sensitive HR data was staged for potential exfiltration through archive creation activity.

**Initiating Process ID:**
```
2533274790396713
```

**MITRE:** T1074 – Data Staged

**KQL:**
```kql
DeviceFileEvents
| where InitiatingProcessAccountName contains "5y51-d3p7"
| where DeviceName contains "sys1-dept"
| where FileName has_any ("zip", "rar")
| project TimeGenerated, ActionType, FileName, InitiatingProcessUniqueId, InitiatingProcessAccountName
| order by TimeGenerated asc 
```

<img width="650" height="300" alt="image" src="https://github.com/user-attachments/assets/ad649907-a86a-4df4-af60-ea39b29decf4" />

---

### FLAG 7 – Outbound Connectivity Test
**Finding:** Outbound connectivity was tested via PowerShell prior to any data transfer attempts.

**First Outbound Attempt Timestamp:**
```
2025-12-03T06:27:31.1857946Z
```

**MITRE:** T1016 – System Network Configuration Discovery

**KQL:**
```kql
DeviceProcessEvents
| where AccountName contains "5y51-d3p7"
| where DeviceName contains "sys1-dept"
| where InitiatingProcessFileName contains "powershell"
| project TimeGenerated, AccountName, FolderPath, FileName, InitiatingProcessCommandLine, InitiatingProcessFileName, ProcessCommandLine
| order by TimeGenerated asc 
```

<img width="650" height="406" alt="image" src="https://github.com/user-attachments/assets/f32caace-3846-45be-8445-adde27096617" />

*after checking process events for the command executed, I correlated the execution time in DeviceProcessEvents with DeviceNetworkEvents to find the answer*


**KQL:**
```kql
DeviceNetworkEvents
| where DeviceName contains "sys1-dept"
| where RemoteUrl contains "example"
| project TimeGenerated, ActionType, RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessFileName, RemoteIP, RemotePort
| order by TimeGenerated asc 
```

<img width="650" height="404" alt="image" src="https://github.com/user-attachments/assets/32d38827-0cae-4d50-ae39-0cb25b333c2e" />

---

### FLAG 8 – Registry-Based Persistence
**Finding:** Persistence was established using a user-level Run key to enable execution on logon.

**Registry Key:**
```
HKEY_CURRENT_USER\S-1-5-21-805396643-3920266184-3816603331-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

**MITRE:** T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys

**KQL:**
```kql
DeviceRegistryEvents
| where InitiatingProcessAccountName contains "5y51-d3p7"
| where DeviceName contains "sys1-dept"
| where RegistryKey contains "run"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc 
```

<img width="800" height="242" alt="image" src="https://github.com/user-attachments/assets/0314e64c-185f-4244-859f-18b11b461cbd" />

---

### FLAG 9 – Scheduled Task Persistence
**Finding:** An additional persistence mechanism was identified through scheduled task creation.

**Task Name:**
```
BonusReviewAssist
```

**MITRE:** T1053.005 – Scheduled Task/Job: Scheduled Task

**KQL:**
```kql
DeviceProcessEvents
| where AccountName contains "5y51-d3p7"
| where DeviceName contains "sys1-dept"
| where InitiatingProcessFileName contains "powershell"
| where FileName contains "schtask"
| project TimeGenerated, AccountName, FolderPath, FileName, InitiatingProcessCommandLine, InitiatingProcessFileName, ProcessCommandLine
| order by TimeGenerated asc 
```

<img width="1000" height="406" alt="image" src="https://github.com/user-attachments/assets/a45951ea-056b-4eec-9b45-1ad6286f1e5a" />

---

### FLAG 10 – Secondary Access to Employee Scorecard Artifact
**Finding:** A different remote session context accessed employee scorecard files, suggesting cross-departmental misuse.

**Remote Session User:**
```
YE-HELPDESKTECH
```

**MITRE:** T1078 – Valid Accounts

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

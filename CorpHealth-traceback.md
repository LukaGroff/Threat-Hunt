# Cyber Range Threat Hunt - CorpHealth: Traceback

<img width="740" height="740" alt="image" src="https://github.com/user-attachments/assets/a4acfe65-91b9-4ba9-addd-e092491df441" />


**Date of Incident:** 23 November 2025  
**Data Source:** Log Analytics workspaces  
**Scope:** Windows endpoint, CorpHealth workstation
**Analyst:** Luka Groff

---

## Executive Overview
Between 23 November and 30 November 2025, a workstation (CH-OPS-WKS02) was accessed using compromised administrative credentials and abused under the guise of legitimate CorpHealth maintenance activity. What initially appeared as off-hours operational telemetry was confirmed to be deliberate, interactive attacker activity involving credential access, privilege escalation, staging, persistence, and command-and-control (C2) setup.
- **What happened (finding)**
- **Why it matters (impact)**
- **MITRE ATT&CK mapping**
- **Representative KQL used to identify the activity**

---

## Attack Timeline & Key Findings

### Initial Access
- Earliest suspicious logon: `2025-11-23T03:08:31Z`
- Source IP: `104.164.168.17`
- Account used: `chadmin`
- Geolocation: `Vietnam`
- Access type: `Remote interactive session (non-local)`

### Early Reconnaissance
- First process launched: `explorer.exe`
- First file accessed: `user-pass.txt`
- Immediate follow-up action: `ipconfig.exe`

### Beaconing & Staging
- First outbound attempt: `2025-11-23T03:46:08Z`
- Successful beacon: `2025-11-30T01:03:17Z`
- Destination: `127.0.0.1:8080` (local relay / staging indicator)
- Primary staged artifact: `C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv`
- Secondary working copy: `C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv`

### Privilege Escalation & Defense Evasion
- Registry tampering under: `HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent`
- Privilege escalation simulation event: `2025-11-23T03:47:21Z`
- Token modification event: token SID = `S-1-5-21-1605642021-30596605-784192815-1000` ; Process ID = `4888`
- Defender exclusion attempted: `C:\ProgramData\Corp\Ops\staging`

### Tooling Deployment & C2
- External tool download via `curl.exe`
- Source: `https://unresuscitating-donnette-smothery.ngrok-free.dev`
- Dropped executable: `revshell.exe`
- Executed via: `explorer.exe`
- External connection attempts: `13.228.171.119:11746`

### Persistence
- Binary copied to Startup folder: `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe`

### Lateral Movement Preparation
- Remote session device name observed: `对手`
- Internal pivot IP identified: `10.168.0.6`
- Secondary account accessed: `ops.maintenance`

---

### FLAG 0 – Identify the Device
**Finding:** Unusual off-hours operational telemetry was isolated to a single workstation.

**Device Identified:**
```
ch-ops-wks02
```

**MITRE:** T1082 – System Information Discovery

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "ch-"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
```

---

### FLAG 1 – Unique Maintenance File
**Finding:** A PowerShell maintenance script was present only on the affected host and not part of baseline CorpHealth deployments

**Artifact Identified:**
```
MaintenanceRunner_Distributed.ps1
```

**MITRE:** T1059.001 – Command and Scripting Interpreter: PowerShell

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "ch-"
| where FileName contains "Maintenance" or ProcessCommandLine contains "Maintenance"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

<img width="900" height="342" alt="image" src="https://github.com/user-attachments/assets/57897069-e297-4f89-93e2-cf188f61cf13" />


---

### FLAG 2 – Outbound Beacon Indicator
**Finding:** The suspicious maintenance script initiated outbound network communication during an unauthorized time window.

**Timestamp Identified:**
```
2025-11-23T03:46:08.400686Z
```

**MITRE:** T1071 – Application Layer Protocol

**KQL:**
```kql
DeviceNetworkEvents
| where DeviceName contains "ch-ops-wks02"
| where InitiatingProcessCommandLine contains "MaintenanceRunner_Distributed.ps1"
| project TimeGenerated, ActionType, InitiatingProcessAccountName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by TimeGenerated asc
```

<img width="900" height="346" alt="image" src="https://github.com/user-attachments/assets/a91488ac-903b-4560-9bd6-8c4109f9780b" />


---

### FLAG 3 – Beacon Destination
**Finding:** The script attempted to establish a beacon connection to a non-standard destination.

**Remote IP & Port:**
```
127.0.0.1:8080
```

**MITRE:** T1090 – Proxy

**KQL:**
Query and results can be seen from flag 2

---

### FLAG 4 – Successful Beacon Timestamp
**Finding:** The latest confirmed successful outbound connection established a potential C2 handshake point.

**Timestamp Identified:**
```
2025-11-30T01:03:17.6985973Z
```

**MITRE:** T1071 – Application Layer Protocol

**KQL:**
same query as flag 2

<img width="900" height="344" alt="image" src="https://github.com/user-attachments/assets/2ffb5201-3077-4f50-a87d-33c6b7540d3b" />


---

### FLAG 5 – Unexpected Staging Activity
**Finding:** The attacker staged diagnostic data in a protected system directory commonly used by CorpHealth.

**Staging File Path:**
```
C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv
```

**MITRE:** T1074.001 – Data Staged: Local Data Staging

**KQL:**
```kql
DeviceFileEvents
| where DeviceName contains "ch-ops-wks02"
| where ActionType contains "filecreated"
| where FolderPath contains "CorpHealth"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="900" height="232" alt="image" src="https://github.com/user-attachments/assets/25e82614-3b08-421b-8f28-273c865baf21" />

---

### FLAG 6 – Staged File Integrity
**Finding:** Cryptographic analysis confirmed the integrity and uniqueness of the staged artifact.

**SHA-256 Hash:**
```
7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8
```

**MITRE:** T1036 – Masquerading

**KQL:**
```kql
DeviceFileEvents
| where DeviceName contains "ch-ops-wks02"
| where ActionType contains "filecreated"
| where FolderPath contains "CorpHealth"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessCommandLine, SHA256
| order by TimeGenerated asc
```
<img width="900" height="292" alt="image" src="https://github.com/user-attachments/assets/ce716686-30fc-4cb4-a988-2e0b3bd921a7" />

---

### FLAG 7 – Duplicate Staged Artifact
**Finding:** A second, similarly named file with a different hash was created in a user temp directory, indicating intermediate processing.

**Secondary File Path:**
```
C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv
```

**MITRE:** T1074.001 – Local Data Staging

**KQL:**
same kql as flag6

<img width="900" height="284" alt="image" src="https://github.com/user-attachments/assets/13f0c90a-2c18-49ce-b03c-8b6a6f1f1566" />


---

### FLAG 8 – Suspicious Registry Activity
**Finding:** A non-standard registry key related to CorpHealth logging was created, consistent with credential or telemetry manipulation.

**Registry Key:**
```
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent
```

**MITRE:** T1112 – Modify Registry

**KQL:**
```kql
DeviceRegistryEvents
| where DeviceName contains "ch-ops-wks02"
| where ActionType contains "RegistryKeyCreated" or ActionType contains "RegistryValueSet"// or ActionType contains "RegistryKeyDeleted"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, PreviousRegistryKey, PreviousRegistryValueName, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```
<img width="900" height="338" alt="image" src="https://github.com/user-attachments/assets/68771941-9418-424c-a239-f2f154cce728" />

---

### FLAG 9 – Scheduled Task Persistence
**Finding:** An unauthorized scheduled task was created to maintain execution persistence.

**Scheduled Task Name:**
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64
```

**MITRE:** T1053.005 – Scheduled Task

**KQL:**
```kql
DeviceRegistryEvents
| where DeviceName contains "ch-ops-wks02"
| where ActionType contains "RegistryKeyCreated" or ActionType contains "RegistryValueSet"// or ActionType contains "RegistryKeyDeleted"
| where RegistryKey contains "schedule"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, PreviousRegistryKey, PreviousRegistryValueName, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```
<img width="900" height="340" alt="image" src="https://github.com/user-attachments/assets/d9c71cd7-900a-4b4d-a718-159eef6e8719" />

---

### FLAG 10 – Registry-based Persistence
**Finding:** A transient Run-key persistence mechanism was created and deleted shortly after execution.

**Registry Value Name:**
```
MaintenanceRunner
```

**MITRE:** T1547.001 – Registry Run Keys / Startup Folder

**KQL:**
```kql
DeviceRegistryEvents
| where DeviceName contains "ch-ops-wks02"
| where ActionType contains "RegistryKeyCreated" or ActionType contains "RegistryValueSet" or ActionType contains "RegistryKeyDeleted"
| where RegistryKey contains "run"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, PreviousRegistryKey, PreviousRegistryValueName, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```
<img width="1000" height="518" alt="image" src="https://github.com/user-attachments/assets/4a0afbce-7795-4757-a305-441c6f8d31fd" />

---

### FLAG 11 – Privilege Escalation Event
**Finding:** A configuration adjustment event indicated simulated privilege escalation activity.

**Timestamp Identified:**
```
2025-11-23T03:47:21.8529749Z
```

**MITRE:** T1068 – Exploitation for Privilege Escalation

**KQL:**
```kql
DeviceEvents
| where DeviceName contains "ch-ops-wks02"
| where AdditionalFields contains "configadjust"
| project TimeGenerated, AdditionalFields, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountSid,InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="900" height="350" alt="image" src="https://github.com/user-attachments/assets/d6e53147-e8e6-4622-97a5-fa51f724dd04" />

---

### FLAG 12 – AV Exclusion Attempt
**Finding:** The attacker attempted to exclude a staging directory from Windows Defender scanning.

**Exclusion Path:**
```
C:\ProgramData\Corp\Ops\staging
```

**MITRE:** T1562.001 – Disable or Modify Tools

**KQL:**
```kql
DeviceProcessEvents
| where AccountDomain contains "ch-ops-wks02"
| where ProcessCommandLine contains "Add-MpPreference"
| project TimeGenerated, AccountDomain,AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath
| order by TimeGenerated asc
```
<img width="900" height="396" alt="image" src="https://github.com/user-attachments/assets/7dbfaeb0-0612-46fe-b9c3-6f2661fe41c4" />

---

### FLAG 13 – Encoded PowerShell Execution
**Finding:** PowerShell executed a Base64-encoded command used for token verification.

**Decoded Command:**
```
Write-Output 'token-6D5E4EE08227'
```

**MITRE:** T1027 – Obfuscated / Encrypted Command

**KQL:**
```kql
DeviceProcessEvents
| where AccountDomain contains "ch-ops-wks02"
| where ProcessCommandLine contains "encoded"
| project TimeGenerated, AccountDomain,AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath
| extend Enc = extract(@"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(Enc)
| order by TimeGenerated asc
```

<img width="900" height="508" alt="image" src="https://github.com/user-attachments/assets/9acb5269-f475-4fbe-a015-0206ffe65eb0" />

---

### FLAG 14 – Privilege Token Modification
**Finding:** A process modified its primary token privileges, indicating privilege escalation behavior.

**InitiatingProcessId:**
```
4888
```

**MITRE:** T1134 – Access Token Manipulation

**KQL:**
```kql
DeviceEvents
| where DeviceName contains "ch-ops-wks02"
| where AdditionalFields contains "tokenChangeDescription" or AdditionalFields contains "Privileges were added"
| where InitiatingProcessCommandLine contains "MaintenanceRunner_Distributed.ps1"
| project TimeGenerated, InitiatingProcessId, InitiatingProcessAccountSid, AdditionalFields, DeviceName, InitiatingProcessAccountName,InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="900" height="402" alt="image" src="https://github.com/user-attachments/assets/13506ffe-6963-4110-84ea-31011b6eb78f" />


---

### FLAG 15 – Modified Token Identity
**Finding:** The modified token belonged to a local user SID rather than a system service account.

**User SID:**
```
S-1-5-21-1605642021-30596605-784192815-1000
```

**MITRE:** T1134 – Access Token Manipulation

**KQL:****
same kql as flag 14, SID can also be seen from the picture provided

---

### FLAG 16 – Ingress Tool Transfer
**Finding:** An unsigned executable was written to disk following external network activity.

**Executable Name:**
```
revshell.exe
```

**MITRE:** T1105 – Ingress Tool Transfer

**KQL (tight + time pivot around payload):**
```kql
DeviceFileEvents
| where DeviceName contains "ch-ops-wks02"
| where FileName contains ".exe"
| where ActionType contains "filecreated"
| where InitiatingProcessCommandLine contains "curl"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, DeviceName
| order by TimeGenerated asc
```
<img width="900" height="394" alt="image" src="https://github.com/user-attachments/assets/ab609fec-3f75-4696-ba53-aab767039f6f" />


---

### FLAG 17 – External Download Source
**Finding:** The payload was retrieved via a dynamic tunneling service using curl.

**Download URL:**
```
https://unresuscitating-donnette-smothery.ngrok-free.dev
```

**MITRE:** T1105 – Ingress Tool Transfer

**KQL:****
kql and answer can be seen in flag 16

---

### FLAG 18 – Execution of Staged Binary
**Finding:** The downloaded binary was executed via a Windows shell process, simulating user interaction.

**Executing Process:**
```
explorer.exe
```

**MITRE:** T1204.002 – User Execution

**KQL:****
```kql
DeviceProcessEvents
| where DeviceName contains "ch-ops-wks02"
| where AccountName contains "chadmin"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="900" height="400" alt="image" src="https://github.com/user-attachments/assets/6961adbd-375c-4a78-af63-5ebe9f5f70e5" />


---

### FLAG 19 – External IP Contacted
**Finding:** The reverse shell attempted outbound communication to a non-standard external IP and port.

**External IP:**
```
13.228.171.119
```

**MITRE:** T1071 – Application Layer Protocol

**KQL (tight + command equality):**
```kql
DeviceNetworkEvents
| where DeviceName contains "ch-ops-wks02"
| where RemotePort == "11746"
| project TimeGenerated, ActionType, InitiatingProcessAccountName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by TimeGenerated asc
```
<img width="900" height="348" alt="image" src="https://github.com/user-attachments/assets/5d452712-8882-4bd9-b09a-aa51b4b1f8fe" />


---

### FLAG 20 – Startup Folder Persistence
**Finding:** The attacker copied the executable into a Startup directory to ensure execution on login.

**Persistence Path:**
```
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe
```

**MITRE:** T1547.001 – Startup Folder

**KQL:****
```kql
DeviceFileEvents
| where DeviceName contains "ch-ops-wks02"
| where FolderPath contains "start" or FolderPath contains "c:\\programdata"
| where FileName contains "revshell.exe"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessAccountName, PreviousFileName
```
<img width="900" height="346" alt="image" src="https://github.com/user-attachments/assets/2294f26b-783c-4e0f-86e3-984bfaa41333" />


---

### FLAG 21 – Remote Session Source Device
**Finding:** Multiple malicious actions shared a consistent remote session identifier.

**Remote Session Device Name:**
```
对手
```

**MITRE:** T1021 – Remote Services

**KQL:****
```kql
DeviceNetworkEvents
| where DeviceName contains "ch-ops-wks02"
| where InitiatingProcessRemoteSessionDeviceName != ""
| project TimeGenerated, ActionType, InitiatingProcessRemoteSessionDeviceName,InitiatingProcessAccountName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by TimeGenerated asc
```
<img width="900" height="684" alt="image" src="https://github.com/user-attachments/assets/aff5aecd-cfcd-4872-9d6f-9edf1f2a6b8c" />


---

### FLAG 22 – Remote Session IP
**Finding:** The attacker consistently accessed the host from a CGNAT relay address.

**Remote Session IP:**
```
100.64.100.6
```

**MITRE:** T1021 – Remote Services

**KQL (tight: only Run/RunOnce + value name):**
```kql
DeviceNetworkEvents
| where DeviceName contains "ch-ops-wks02"
| where InitiatingProcessRemoteSessionDeviceName == "对手"
| where InitiatingProcessRemoteSessionIP !startswith "10."
| project TimeGenerated, ActionType, InitiatingProcessRemoteSessionDeviceName,InitiatingProcessRemoteSessionIP, InitiatingProcessAccountName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by TimeGenerated asc
```
<img width="900" height="472" alt="image" src="https://github.com/user-attachments/assets/e6c5eae3-0561-412c-bf3d-2bfc7bc1cc43" />


---

### FLAG 23 – Internal Pivot Host
**Finding:** Telemetry revealed an internal Azure IP used as a pivot during remote sessions.

**Internal Pivot IP:**
```
10.168.0.6
```

**MITRE:** T1021.001 – Remote Desktop Protocol

**KQL:**
```kql
DeviceNetworkEvents
| where DeviceName contains "ch-ops-wks02"
| where InitiatingProcessRemoteSessionDeviceName == "对手"
| where InitiatingProcessRemoteSessionIP !startswith "100.64"
| project TimeGenerated, ActionType, InitiatingProcessRemoteSessionDeviceName,InitiatingProcessRemoteSessionIP, InitiatingProcessAccountName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by TimeGenerated asc
```
<img width="900" height="408" alt="image" src="https://github.com/user-attachments/assets/1b662c8e-44a3-43a3-b11b-ecf3cf613af4" />

---

### FLAG 24 – First Suspicious Logon
**Finding:** The earliest confirmed malicious logon marks the start of the intrusion.

**Timestamp Identified:**
```
2025-11-23T03:08:31.1849379Z
```

**MITRE:** T1078 – Valid Accounts

**KQL:**
```kql
DeviceLogonEvents
| where DeviceName contains "ch-ops-wks02"
| where ActionType contains "success"
| where RemoteIP != ""
| project TimeGenerated, ActionType, AccountDomain, AccountName, DeviceName, InitiatingProcessCommandLine, LogonType, RemoteIP
| order by TimeGenerated asc
```
<img width="800" height="406" alt="image" src="https://github.com/user-attachments/assets/19d5010d-3d1e-44ec-8a47-39af3c8ce4b7" />

---

### FLAG 25 – Initial Logon Source IP
**Finding:** The first logon originated from an external public IP.

**Source IP:**
```
104.164.168.17
```

**MITRE:** T1078 – Valid Accounts

**KQL:**
KQL and the answer can be seen from flag 24.

---

### FLAG 26 – Compromised Account
**Finding:** A privileged local account was used for the initial access

**Account Name:**
```
chadmin
```

**MITRE:** T1078 – Valid Accounts

**KQL:**
KQL and the answer can be seen in flag 24.

---

### FLAG 27 – Attacker Geographic Region
**Finding:** IP enrichment revealed a consistent geographic origin.

**Region Identified:**
```
Vietnam
```

**MITRE:** T1598 – Network Information Discovery

**KQL:**
KQL can be seen in flag 24. The location of the IP was found on the website IPlocation.net

---

### FLAG 28 – First Process After Logon
**Finding:** The attacker initiated an interactive desktop session immediately after login.

**Process Name:**
```
explorer.exe
```

**MITRE:** T1059 – Command and Scripting Interpreter

**KQL:**
```kql
DeviceProcessEvents
| where AccountDomain contains "ch-ops-wks02"
| where InitiatingProcessAccountName contains "chadmin"
| project TimeGenerated, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath
| order by TimeGenerated asc
```
<img width="900" height="292" alt="image" src="https://github.com/user-attachments/assets/410cd182-b767-49b2-886a-c7a9620680af" />


---

### FLAG 29 – First File Accessed
**Finding:** The attacker accessed a file containing credential-related information.

**File Name:**
```
user-pass.txt
```

**MITRE:** T1552.001 – Credentials in Files

**KQL:**
```kql
DeviceFileEvents
| where InitiatingProcessId == "5732"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, DeviceName
| order by TimeGenerated asc
```
<img width="900" height="560" alt="image" src="https://github.com/user-attachments/assets/b22c71db-9359-4d08-ae90-f69579a598bc" />

---

### FLAG 30 – Post-Credential Action
**Finding:** The attacker executed a network configuration command following credential access.

**Action Identified:**
```
ipconfig.exe
```

**MITRE:** T1082 – System Information Discovery

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "ch-ops-wks02"
| where AccountName contains "chadmin"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

<img width="900" height="464" alt="image" src="https://github.com/user-attachments/assets/c3242cb3-42f7-4bfe-be96-583ed4004d22" />


---

### FLAG 31 – Next Account Accessed
**Finding:** The attacker pivoted to a secondary operational account after reconnaissance.

**Account Name:**
```
ops.maintenance
```

**MITRE:** T1078 – Valid Accounts

**KQL:**
```kql
DeviceLogonEvents
| where DeviceName contains "ch-ops-wks02"
| where ActionType contains "success"
| where RemoteIP != ""
| project TimeGenerated, ActionType, AccountDomain, AccountName, DeviceName, InitiatingProcessCommandLine, LogonType, RemoteIP
| order by TimeGenerated asc
```
<img width="900" height="552" alt="image" src="https://github.com/user-attachments/assets/efc7ea07-d22e-4a6f-9348-321e3c86faac" />


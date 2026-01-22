# Cyber Range Threat Hunt - CorpHealth: Traceback

<img width="740" height="740" alt="image" src="https://github.com/user-attachments/assets/a4acfe65-91b9-4ba9-addd-e092491df441" />


**Date of Incident:** 23 November 2025  
**Data Source:** Log Analytics workspaces  
**Scope:** Windows endpoint, CorpHealth workstation

---

## Executive Overview
Between 23 November and 30 November 2025, a workstation (CH-OPS-WKS02) was accessed using compromised administrative credentials and abused under the guise of legitimate CorpHealth maintenance activity. What initially appeared as off-hours operational telemetry was confirmed to be deliberate, interactive attacker activity involving credential access, privilege escalation, staging, persistence, and command-and-control (C2) setup.
- **What happened (finding)**
- **Why it matters (impact)**
- **MITRE ATT&CK mapping**
- **Representative KQL used to identify the activity**

This format is suitable both as a **GitHub README** and as the narrative core of a **PDF-style SOC incident report**.

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

**CDevice Identified:**
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
<img width="800" height="518" alt="image" src="https://github.com/user-attachments/assets/4a0afbce-7795-4757-a305-441c6f8d31fd" />

---

### FLAG 12 – Backup Service Disabled
**Finding:** The attacker disabled cron to prevent scheduled jobs from starting on boot (persistent).

**Command:**
```
systemctl disable cron
```

**MITRE:** T1489 – Service Stop

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where AccountName == "backup-admin"
| where ProcessCommandLine == "systemctl disable cron"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

## PHASE 2 – Windows Ransomware Deployment (FLAGS 13–15)

### FLAG 13 – Remote Execution Tool
**Finding:** PsExec was used for lateral command execution over admin shares.

**Tool:**
```
PsExec64.exe
```

**MITRE:** T1021.002 – SMB / Windows Admin Shares

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where FileName =~ "PsExec64.exe" or ProcessCommandLine has "PsExec64.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

---

### FLAG 14 – Deployment Command
**Finding:** The attacker used PsExec to copy and execute the ransomware payload on remote systems.

**Command (password redacted):**
```
"PsExec64.exe" \10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe
```

**MITRE:** T1021.002 – SMB / Windows Admin Shares

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where FileName =~ "PsExec64.exe" or ProcessCommandLine has "PsExec64.exe"
| where ProcessCommandLine has "\\10.1.0.102" and ProcessCommandLine has "silentlynx.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 15 – Malicious Payload
**Finding:** The ransomware binary name was identified for environment-wide hunting.

**Payload:**
```
silentlynx.exe
```

**MITRE:** T1204.002 – User Execution (Malicious File)

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where FileName =~ "silentlynx.exe" or ProcessCommandLine has "silentlynx.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

---

## PHASE 3 – Recovery Inhibition (FLAGS 16–22)

### FLAG 16 – Shadow Service Stopped
**Finding:** The ransomware stopped the Volume Shadow Copy Service to prevent snapshot-based recovery during encryption.

**Command:**
```
"net" stop VSS /y
```

**MITRE:** T1490 – Inhibit System Recovery

**KQL:****
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where ProcessCommandLine == '"net" stop VSS /y'
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 17 – Backup Engine Stopped
**Finding:** Windows Backup Engine was stopped to halt backup operations and dependent services.

**Command:**
```
"net" stop wbengine /y
```

**MITRE:** T1490 – Inhibit System Recovery

**KQL (tight + time pivot around payload):**
```kql
let AzukiDevices = dynamic(["azuki-adminpc","azuki-fileserver","azuki-logisticspc","azuki-backup"]);
let AnchorTime = toscalar(
    DeviceProcessEvents
    | where DeviceName in~ (AzukiDevices)
    | where ProcessCommandLine has "silentlynx.exe"
    | summarize max(TimeGenerated)
);
let Win = 45m;
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where TimeGenerated between (AnchorTime-Win .. AnchorTime+Win)
| where ProcessCommandLine == '"net" stop wbengine /y'
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 18 – Process Termination (Unlock Files)
**Finding:** Database services were forcefully terminated to release file locks prior to encryption.

**Command:**
```
"taskkill" /F /IM sqlservr.exe
```

**MITRE:** T1562.001 – Impair Defenses (Disable or Modify Tools)

**KQL:****
```kql
let AzukiDevices = dynamic(["azuki-adminpc","azuki-fileserver","azuki-logisticspc","azuki-backup"]);
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where ProcessCommandLine == '"taskkill" /F /IM sqlservr.exe'
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 19 – Recovery Point Deletion
**Finding:** All existing shadow copies were deleted to remove local restore points.

**Command:**
```
"vssadmin" delete shadows /all /quiet
```

**MITRE:** T1490 – Inhibit System Recovery

**KQL:****
```kql
let AzukiDevices = dynamic(["azuki-adminpc","azuki-fileserver","azuki-logisticspc","azuki-backup"]);
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where ProcessCommandLine == '"vssadmin" delete shadows /all /quiet'
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 20 – Storage Limitation
**Finding:** Shadow storage was resized to prevent creation of new recovery points.

**Command:**
```
"vssadmin" resize shadowstorage /for=C: /on=C: /maxsize=401MB
```

**MITRE:** T1490 – Inhibit System Recovery

**KQL (tight + command equality):**
```kql
let AzukiDevices = dynamic(["azuki-adminpc","azuki-fileserver","azuki-logisticspc","azuki-backup"]);
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where ProcessCommandLine == '"vssadmin" resize shadowstorage /for=C: /on=C: /maxsize=401MB'
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 21 – Recovery Disabled
**Finding:** Windows recovery features were disabled to block automatic repair after system corruption.

**Command:**
```
"bcdedit" /set {default} recoveryenabled No
```

**MITRE:** T1490 – Inhibit System Recovery

**KQL:****
```kql
let AzukiDevices = dynamic(["azuki-adminpc","azuki-fileserver","azuki-logisticspc","azuki-backup"]);
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where FileName in~ ("bcdedit.exe","cmd.exe")
| where ProcessCommandLine == '"bcdedit" /set {default} recoveryenabled No'
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 22 – Catalog Deletion
**Finding:** The Windows Backup catalog was deleted, making backups undiscoverable even if files remained.

**Command:**
```
"wbadmin" delete catalog -quiet
```

**MITRE:** T1490 – Inhibit System Recovery

**KQL:****
```kql
let AzukiDevices = dynamic(["azuki-adminpc","azuki-fileserver","azuki-logisticspc","azuki-backup"]);
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where FileName in~ ("wbadmin.exe","cmd.exe")
| where ProcessCommandLine == '"wbadmin" delete catalog -quiet'
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```



---

## PHASE 4 – Persistence (FLAGS 23–24)

### FLAG 23 – Registry Autorun
**Finding:** A Run-key style autorun value masqueraded as a Windows security component to persist across reboots.

**Registry Value Name:**
```
WindowsSecurityHealth
```

**MITRE:** T1547.001 – Registry Run Keys / Startup Folder

**KQL (tight: only Run/RunOnce + value name):**
```kql
let AzukiDevices = dynamic(["azuki-adminpc","azuki-fileserver","azuki-logisticspc","azuki-backup"]);
DeviceRegistryEvents
| where DeviceName in~ (AzukiDevices)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (
    "\Software\Microsoft\Windows\CurrentVersion\Run",
    "\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
| where RegistryValueName == "WindowsSecurityHealth"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

### FLAG 24 – Scheduled Task Persistence
**Finding:** A scheduled task was created to ensure the ransomware (or helper component) re-executes reliably.

**Task Path:**
```
\Microsoft\Windows\Security\SecurityHealthService
```

**MITRE:** T1053.005 – Scheduled Task/Job

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where FileName =~ "schtasks.exe" or ProcessCommandLine has "schtasks"
| where ProcessCommandLine has_any ("/create","/Create")
| where ProcessCommandLine has "SecurityHealthService"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

**KQL (registry pivot confirming the full task path):**
```kql
DeviceRegistryEvents
| where DeviceName in~ (AzukiDevices)
| where RegistryKey has "\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
| where RegistryKey has "\Microsoft\Windows\Security\SecurityHealthService"
| project TimeGenerated, DeviceName, ActionType, RegistryKey, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

## PHASE 5 – Anti‑Forensics (FLAG 25)

### FLAG 25 – Journal Deletion
**Finding:** The NTFS USN Journal was deleted to remove forensic artifacts that track file system changes.

**Command:**
```
"fsutil.exe" usn deletejournal /D C:
```

**MITRE:** T1070.004 – Indicator Removal on Host (File Deletion)

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName in~ (AzukiDevices)
| where ProcessCommandLine has_all ("fsutil","usn","deletejournal")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

## PHASE 6 – Ransomware Success (FLAG 26)

### FLAG 26 – Ransom Note
**Finding:** Ransom note artifacts confirm successful encryption and provide attacker instructions.

**Filename:**
```
SILENTLYNX_README.txt
```

**MITRE:** T1486 – Data Encrypted for Impact

**KQL:**
```kql
DeviceFileEvents
| where DeviceName in~ (AzukiDevices)
| where FileName == "SILENTLYNX_README.txt"
| project TimeGenerated, DeviceName, ActionType, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

## Conclusion
This incident demonstrates a **methodical, multi‑stage ransomware operation** with deliberate focus on:
- Backup and recovery destruction **before** encryption
- Rapid lateral deployment via admin tooling
- Persistent access and anti‑forensic cleanup

The attacker achieved full operational impact with minimal resistance, underscoring gaps in backup isolation, credential hygiene, and endpoint monitoring.

---

*Prepared as a SOC investigation walkthrough and portfolio‑ready incident report.*

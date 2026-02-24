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

<img width="400" height="674" alt="image" src="https://github.com/user-attachments/assets/a33bfa3b-12aa-4154-8873-cb2532d3882c" />

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

The attacker used the built-in Windows utility certutil.exe to download the malicious payload from the external staging domain (sync.cloud-endpoint.net) and saved it locally as RuntimeBroker.exe in C:\Users\Public\ (flag 10). This demonstrates tool transfer via a living-off-the-land binary and renaming of the payload for evasion and persistence.

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

---

### FLAG 11 – Credential Extraction Execution Identity
**Finding:** Credential dumping activity was performed under a specific user context, confirming which account was actively operating during registry hive access and staging operations. **The answer can be seen in flag 1**

**User Identified:**
```
Sophie.Turner
```

**MITRE:** T1078 – Valid Accounts

---

## SECTION 4: DISCOVERY [Moderate]

---

### FLAG 12 – Post-Compromise Identity Verification
**Finding:** After establishing execution, the attacker validated the current security context to confirm privileges and determine their access level on the compromised system. **The answer can be seen in Flag 1**

**Command Observed:**
```
whoami
```

**MITRE:** T1033 – System Owner/User Discovery

---

### FLAG 13 – Network Share Enumeration
**Finding:** The attacker enumerated available network shares to identify accessible resources and potential lateral movement targets within the environment. **The answer can be seen in Flag 1**

**Command Observed:**
```
net.exe view
```

**MITRE:** T1135 – Network Share Discovery

---

### FLAG 14 – Privileged Group Enumeration
**Finding:** The attacker queried local privileged group membership to identify accounts with administrative rights, supporting potential privilege escalation or lateral movement planning. **The answer can be seen in Flag 1**

**Group Queried:**
```
administrators
```

**MITRE:** T1069.001 – Permission Groups Discovery: Local Groups

---

## SECTION 5: PERSISTENCE - REMOTE TOOL [Hard]

---

### FLAG 15 – Remote Administration Tool Deployment
**Finding:** A legitimate remote administration tool was installed to ensure persistent interactive access to compromised systems. This provided the attacker with long-term control beyond the initial malware execution. **The answer can be seen in Flag 1**

**Software Identified:**
```
AnyDesk.exe
```

**MITRE:** T1219 – Remote Access Software

**Alerts**

<img width="300" alt="image" src="https://github.com/user-attachments/assets/8d622a15-fbaf-49cf-a11c-01a507b02ba5" />

<img width="300" alt="image" src="https://github.com/user-attachments/assets/5a88a42c-6677-4d12-b0d8-97ca4807b491" />

---

### FLAG 16 – Remote Tool Hash Identification
**Finding:** The deployed remote access software was uniquely fingerprinted using its SHA256 hash, enabling confirmation of the exact binary used across affected systems.

**SHA256 Identified:**
```
f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532
```

**MITRE:** T1219 – Remote Access Software

---

### FLAG 17 – Living-off-the-Land Download Method
**Finding:** The attacker leveraged a native Windows binary to retrieve the remote access tool from external infrastructure. This technique blends malicious activity with legitimate system utilities to evade detection. **The answer can be seen in Flag 1**

**Binary Used:**
```
certutil.exe
```

---

### FLAG 18 – Remote Tool Configuration Access
**Finding:** After deployment, the attacker accessed the AnyDesk configuration file to enable unattended access, ensuring persistent remote connectivity without user interaction. **The answer can be seen in Flag 1**

**Configuration File Path:**
```
C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf
```

**MITRE:** T1546 – Event-Triggered Execution

---

### FLAG 19 – Unattended Access Credential Configuration
**Finding:** The attacker configured unattended access within the remote administration tool, setting a persistent authentication credential to maintain remote control without user approval. **The answer can be seen in Flag 1**

**Password Set:**
```
intrud3r!
```

**MITRE:** T1098 – Account Manipulation

---

### FLAG 20 – Remote Tool Deployment Footprint
**Finding:** The remote administration tool was deployed across multiple systems within the environment, indicating deliberate expansion of persistent access beyond the initial compromise point.

**Hostnames Identified:**
```
as-pc1, as-pc2, as-srv
```

**MITRE:** T1021 – Remote Services

**KQL:**
```kql
DeviceProcessEvents
| where FileName =~ "AnyDesk.exe"
| summarize by DeviceName
```

<img width="300" height="232" alt="image" src="https://github.com/user-attachments/assets/a4019c1e-88d3-4b8c-a94d-de49f176cf8f" />

---

## SECTION 6: LATERAL MOVEMENT [Advanced]

---

### FLAG 21 – Failed Remote Execution Attempts
**Finding:** The attacker attempted lateral movement using multiple native remote execution utilities. Telemetry shows unsuccessful attempts using both WMI and SMB-based remote execution before pivoting to another method.

**Tools Attempted:**
```
WMIC.exe, PsExec.exe
```

**MITRE:** MITRE: T1047 – Windows Management Instrumentation & T1021.002 – SMB/Windows Admin Shares

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "as-pc"
| where AccountName contains "sophie"
| project
    TimeGenerated,
    ActionType,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    FolderPath,
    SHA256,
    InitiatingProcessSHA256,
    InitiatingProcessParentId,
    InitiatingProcessParentFileName
| order by TimeGenerated asc
```

<img width="900" height="754" alt="image" src="https://github.com/user-attachments/assets/17dfd6de-6a64-4bc4-a2e7-168d63294fa5" />

---

### FLAG 22 – Target Host of Failed Lateral Movement
**Finding:** Remote execution attempts were directed at a specific workstation within the environment. Telemetry confirms this system as the intended pivot target prior to successful lateral movement. **The answer can be seen in Flag 21**

**Target Host Identified:**
```
AS-PC2
```

**MITRE:** T1021 – Remote Services

---

### FLAG 23 – Successful Lateral Movement Method
**Finding:** After unsuccessful remote execution attempts, the attacker successfully pivoted using Remote Desktop Protocol (RDP), establishing interactive access to the target system. **The answer can be seen in Flag 21**

**Process Used:**
```
mstsc.exe
```

**MITRE:** T1021.001 – Remote Desktop Protocol

---

### FLAG 24 – Lateral Movement Path Reconstruction
**Finding:** Correlation of authentication logs, remote session activity, and process telemetry confirms the sequential movement of the attacker across multiple systems within the environment.

**Movement Path Identified:**
```
as-pc1>as-pc2>as-srv
```

**MITRE:** T1021 – Remote Services

---


### FLAG 25 – Valid Account Used for Lateral Movement
**Finding:** Successful authentication during lateral movement was performed using a legitimate domain account, indicating credential compromise and reuse rather than exploitation of a vulnerability.

**Account Identified:**
```
david.mitchell
```

**MITRE:** T1078 – Valid Accounts

---

### FLAG 26 – Disabled Account Reactivation
**Finding:** A previously disabled account was re-enabled to facilitate continued access within the environment. This modification was performed using the native net.exe utility.

**Parameter Used:**
```
active:yes
```

**MITRE:** T1098 – Account Manipulation

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "as-pc"
| where AccountName contains "david"
| project
    TimeGenerated,
    ActionType,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    FolderPath,
    SHA256,
    InitiatingProcessSHA256,
    InitiatingProcessParentId,
    InitiatingProcessParentFileName
| order by TimeGenerated asc
```

<img width="900" height="758" alt="image" src="https://github.com/user-attachments/assets/c5bd9cd1-dbbc-4a53-af20-b1bd1ec97479" />

---

### FLAG 27 – Account Activation Execution Context
**Finding:** Telemetry confirms that the account reactivation was executed under a valid user session, identifying the operator responsible for enabling continued access. **The answer can be seen in Flag 26**

**User Identified:**
```
david.mitchell
```

**MITRE:** T1078 – Valid Accounts

---

## SECTION 7: PERSISTENCE - SCHEDULED TASK [Hard]

---

### FLAG 28 – Scheduled Task Persistence
**Finding:** A scheduled task was created to ensure recurring execution of a malicious payload, establishing automated persistence independent of user interaction.

**Task Name Identified:**
```
MicrosoftEdgeUpdateCheck
```

**MITRE:** T1053.005 – Scheduled Task/Job: Scheduled Task

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "as-pc"
| where AccountName contains "david"
| project
    TimeGenerated,
    ActionType,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    FolderPath,
    SHA256,
    InitiatingProcessSHA256,
    InitiatingProcessParentId,
    InitiatingProcessParentFileName
| order by TimeGenerated asc
```

<img width="900" height="786" alt="image" src="https://github.com/user-attachments/assets/f34b7f03-bb54-4f2b-968d-83e0cde87a8f" />

---

### FLAG 29 – Masqueraded Persistence Binary
**Finding:** The persistence payload was renamed to resemble a legitimate Windows system process, reducing the likelihood of detection during casual inspection.  **The answer can be seen in Flag 28**

**Filename Used:**
```
RuntimeBroker.exe
```

**MITRE:** T1036 – Masquerading

---

### FLAG 30 – Persistence Payload Hash Correlation
**Finding:** The renamed persistence binary was confirmed to share the same SHA256 hash as the original malicious payload, proving reuse of the initial malware for continued access.

**SHA256 Identified:**
```
48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5
```

**MITRE:** T1036 – Masquerading

**KQL:**
```kql
DeviceFileEvents
| where DeviceName contains "as-pc"
| where SHA256 contains "48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5"
| where InitiatingProcessAccountName has_any ("sophie", "david")
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain ,FileName, FolderPath, InitiatingProcessCommandLine, PreviousFileName, PreviousFolderPath, SHA256
```

<img width="900" height="260" alt="image" src="https://github.com/user-attachments/assets/2e12f663-2364-4835-ae85-765a43e995f3" />

---

### FLAG 31 – Backdoor Account Creation
**Finding:** A new local account was created to provide persistent access independent of the original compromised credentials, ensuring continued control even if other mechanisms were discovered. **The answer can be seen in Flag 1**

**Username Identified:**
```
svc_backup
```

**MITRE:** T1136.001 – Create Account: Local Account

---

## SECTION 8: DATA ACCESS [Hard]

---

### FLAG 32 – Sensitive Document Access
**Finding:** The attacker accessed a sensitive financial spreadsheet located on the file server, indicating data targeting beyond credential theft and system control. 

**Filename Identified:**
```
BACS_Payments_Dec2025.ods
```

Command used: `"soffice.exe" -o "\\AS-SRV\Payroll\BACS_Payments_Dec2025.ods"` **The answer can be seen in Flag 26 & 28**

**MITRE:** T1213 – Data from Information Repositories

---

### FLAG 33 – Evidence of Document Modification
**Finding:** A temporary lock file was created alongside the sensitive spreadsheet, confirming the document was opened in edit mode rather than merely viewed.

**Artifact Identified:**
```
.~lock.BACS_Payments_Dec2025.ods#
```

**MITRE:** T1074.001 – Data Staged: Local Data Staging

**KQL:**
```kql
DeviceFileEvents
| where DeviceName contains "as-srv"
| where FileName contains "BACS"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain ,FileName, FolderPath, InitiatingProcessCommandLine, PreviousFileName, PreviousFolderPath, SHA256
```

<img width="650" height="698" alt="image" src="https://github.com/user-attachments/assets/e5380ee5-cdc5-4905-8932-fb4203ef730d" />

---

### FLAG 34 – Workstation Origin of Data Access
**Finding:** File access telemetry confirms that the sensitive spreadsheet was opened from a specific workstation, identifying the source system involved in the data access activity.

**Hostname Identified:**
```
as-pc2
```

**MITRE:** T1021 – Remote Services

---

### FLAG 35 – Data Archiving for Exfiltration
**Finding:** Prior to potential data exfiltration, the attacker compressed collected files into an archive, indicating staging of sensitive information for transfer outside the environment.

**Archive Identified:**
```
Shares.7z
```

**MITRE:** T1560.001 – Archive Collected Data: Archive via Utility

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "as-srv"
| where AccountName contains "as.srv.administrator"
| project
    TimeGenerated,
    ActionType,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    FolderPath,
    SHA256,
    InitiatingProcessSHA256,
    InitiatingProcessParentId,
    InitiatingProcessParentFileName
| order by TimeGenerated asc
```

<img width="750" height="682" alt="image" src="https://github.com/user-attachments/assets/212a9024-95fe-4127-9607-2087986decab" />

---

### FLAG 36 – Staged Archive Hash Identification
**Finding:** The compressed archive created for data staging was uniquely identified via its SHA256 hash, enabling correlation of the artifact across telemetry and confirming the integrity of the staged data package.

**SHA256 Identified:**
```
6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048
```

**MITRE:** T1560.001 – Archive Collected Data: Archive via Utility

---

### FLAG 37 – Log Clearing Activity
**Finding:** The attacker cleared critical Windows event logs to remove forensic evidence of their activity, indicating deliberate anti-forensics behavior prior to completing the operation.

**Logs Cleared:**
```
security, system
```

**MITRE:** T1070.001 – Indicator Removal: Clear Windows Event Logs

---



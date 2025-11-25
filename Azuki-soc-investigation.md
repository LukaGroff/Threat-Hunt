# SOC Incident Investigation – Azuki Import/Export Compromise

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
|------------|-------|--------|-----------------|
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




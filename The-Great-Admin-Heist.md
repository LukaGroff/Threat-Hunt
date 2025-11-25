 # 🎯 Threat-Hunting-Scenario-The-Great-Admin-Heist

<img width="400" src="https://github.com/user-attachments/assets/1f05cb00-e1af-40f1-a4e1-8f24f6528a57" alt="computer login screen"/>

# 🕵️ **Scenario: APT Threat Alert** 🚨  
**Date**: 7 May 2025  
**Target User**: Bubba Rockerfeatherman III (anthony-001)  
**Scenario**: Acme Corp - Phantom Hackers APT Intrusion

## Platforms and Languages Leveraged
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

## Executive Summary

Acme Corp has experienced a targeted attack by the advanced persistent threat (APT) group known as The Phantom Hackers. Through stealthy delivery, deceptive tools, and persistent mechanisms, the attackers successfully infiltrated a privileged system used by the IT administrator Bubba Rockerfeatherman III.

This investigation, conducted using MDE telemetry and KQL queries, uncovered a multi-stage attack that began with a fake antivirus binary and progressed into system modification, keylogging, and long-term persistence through scheduled tasks and registry manipulation. All malicious behaviors were traced back to the execution of a single binary: BitSentinelCore.exe.

## Threat Timeline

**Timestamp(UTC)**            |   **Event Description**  
2025-05-07T02:00:36.794406Z    |   File BitSentinelCore.exe was created (Fake Antivirus)  
2025-05-07T02:02:14.9669902Z  |   Registry key modified in HKCU\...\Run for persistence  
2025-05-07T02:02:15.2599627Z  |   cmd.exe spawns and creates Scheduled Task UpdateHealthTelemetry  
2025-05-07T02:06:51.3594039Z  |   File systemreport.lnk was dropped to serve as a keylogger  

---

## 🧠 Your mission:
Hunt through Microsoft Defender for Endpoint (MDE) telemetry, analyze signals, query using KQL, and follow the breadcrumbs before the keys to Bubba’s empire vanish forever.

### High-Level Related IoC Discovery Plan
- **Check `DeviceProcessEvents`** for any new processes.
- **Check `DeviceRegistryEvents`** for any modified keys.
- **Check `DeviceFileEvents`** for any file changes.

---

### 🕵️ **Flag 1: Identify the Fake Antivirus Program Name** 🔍  
**What to Hunt**: Look for the name of the suspicious file or binary that resembles an antivirus but is responsible for the malicious activity.

I looked for the answer under DeviceFileEvents with the user anthony-001. With the help of the hint of the program's name starting with either A, B, or C, and assuming it's an executable (exe) fil,e I used the following KQL to find the answer

```
DeviceFileEvents
| where DeviceName == "anthony-001"
| where ActionType == "FileCreated"
| where FileName startswith "A" or FileName startswith "B" or FileName startswith "C"
| where FileName contains ".exe"
```
<img width="800" src="https://github.com/user-attachments/assets/b5424ba6-a943-4e48-8f67-3cb820fac499"/>

**Answer**: BitSentinelCore.exe  
**Details**: Disguised as an antivirus tool, this executable initiated the malicious chain of events.

---


### 🕵️ **Flag 2: Malicious File Written Somewhere** 🔍 
**What to Hunt**: Identify the one responsible for dropping the malicious file into the disk.
I just looked specifically for the BitSentinelCore.exe file and filtered for some of the more interesting fields.

```
DeviceFileEvents
| where DeviceName == "anthony-001"
| where FileName == "BitSentinelCore.exe"
| project Timestamp, FileName, InitiatingProcessFolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```

<img width="800" src="https://github.com/user-attachments/assets/a7c6ee66-c07b-462f-a7d7-6d32d86dacdc"/>

**Answer**: csc.exe  
**Details**: Used to compile and drop BitSentinelCore.exe into the C:\ProgramData directory.

---


### 🕵️ **Flag 3: Execution of the Program** 🔍 
**What to Hunt**: Search for process execution events tied to the suspicious binary.

The file was executed by Bubba himself, as can be seen in the results of the DeviceProcessEvents. This one was pretty straightforward, especially with the hint being obvious.

```
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName == "BitSentinelCore.exe"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc
```

<img width="800" src="https://github.com/user-attachments/assets/bd376a6a-7110-4d4e-af6a-ee72efceb0e2"/>

**Answer**: BitSentinelCore.exe  
**Details**: Manually executed by the user (Bubba), confirming attacker deception and delivery success.

---

### 🕵️ **Flag 4: Keylogger Artifact Written** 🔍 
**What to Hunt**: Search for any file write events associated with possible keylogging activity.
**Hints**:
1. "a rather efficient way to completing a complex process"
2. News

This one took me a very long time to find the file. Initially, I thought that the BitSentinelCore.exe was the InitiatingProcessFileName, so I went through many different filter possibilities, eliminating some file extensions as I went. From the hint, I already figured that it's either an automated task OR some kind of zip or rar file, so I looked into those. The News hint was also trying to act as a honeypot, where a suspicious file actually had the word News in it. After running around for like 2 hours, I took a long break. When I came back, I looked into what file extensions are usually used for keyloggers, so I looked for all of those, without the InitiatingProcessFileName filter, and it narrowed down the results enough for me to find the right file, which was blending in very well.

```
DeviceFileEvents
| where DeviceName == "anthony-001"
| where FileName endswith ".zip" or FileName endswith ".rar" or FileName endswith ".7z" or FileName endswith ".docm" or FileName endswith ".xlsm" or FileName endswith ".hta" or FileName endswith ".lnk"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```

<img width="800" src="https://github.com/user-attachments/assets/c0518d21-b57c-413b-8350-7caf38a25e41"/>

**Answer**: systemreport.lnk  
**Details**: A disguised .lnk file written to the user’s recent documents folder, consistent with keylogging tactics.

---


### 🕵️ **Flag 5: Registry Persistence Entry** 🔍 
**What to Hunt**: Look for registry modifications that enable the malware to auto-run on startup.

I looked into DeviceRegistryEvents for any registry keys containing Run or Winlogon, as is consistent with registry persistence. I quickly saw the one that stood out.

```
DeviceRegistryEvents
| where DeviceName == "anthony-001"
| where RegistryKey contains "Run" or RegistryKey contains "Winlogon"
| where ActionType == "RegistryValueSet"
| order by Timestamp asc
```

<img width="800" src="https://github.com/user-attachments/assets/ba5195b3-4e7b-41b2-8f8d-fd405cbe9acb"/>

**Answer**: HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run  
**Details**: Entry created here causes the malware to execute at every user login, achieving persistence.

---

### 🕵️ **Flag 6: Daily Scheduled Task Created** 🔍 
**What to Hunt**: Identify name of the associated scheduled task.

This one was pretty easy to look for with the ProcessCommandLine containing "schtasks". With filtering for the InitiatingProcessCommandLine I could see the name of the scheduled task.

```
DeviceProcessEvents
|where DeviceName == "anthony-001"
| where ProcessCommandLine contains "schtasks" or ProcessCommandLine contains "Register-ScheduledTask"
| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine
```

<img width="800" src="https://github.com/user-attachments/assets/52bafa46-9ba9-4bbd-ade6-560a76799824"/>

**Answer**: UpdateHealthTelemetry  
**Details**: Task created using schtasks.exe, scheduled to execute BitSentinelCore.exe daily.

---


### 🕵️ **Flag 7: Process Spawn Chain** 🔍
**What to Hunt**: Trace the parent process that led to cmd.exe, and subsequently to schtasks.exe

Upon inspecting the results from the previous step, I found 2 different but similar parent-child processes. I just had to remove the project filter, and I could see the full process tree of each record.

```
DeviceProcessEvents
|where DeviceName == "anthony-001"
| where ProcessCommandLine contains "schtasks" or ProcessCommandLine contains "Register-ScheduledTask"
```

<img width="800" src="https://github.com/user-attachments/assets/cc996fed-8f98-48dc-bfca-96fd1c8d7360"/>

**Answer**: BitSentinelCore.exe -> cmd.exe -> schtasks.exe  
**Details**: Clear parent-child-grandchild relationship showing malware-initiated persistence setup.


### 🕵️ **Flag 8: Timestamp Correlation** 🔍
**What to Hunt**: Compare timestamps from the initial execution to file creation, registry modification, and task scheduling.

From all the results of the previous steps, I took notes of the timeline and have already added it at the beginning of the report, right under the summary, to quickly see the summary and timeline of the events. 
As for the question of when it all began, it can be seen below.

**Answer**: 2025-05-07T04:00:36.794406Z  
**Details**: The timestamp at which BitSentinelCore.exe was executed, triggering the full attack chain.


## Conclusion

This threat hunt successfully uncovered a stealthy and multi-layered intrusion orchestrated by The Phantom Hackers. Every malicious behavior—from initial execution, to keylogger deployment, to persistent access—was definitively linked to the execution of the fake antivirus BitSentinelCore.exe. The attack leveraged common techniques in a clever way to maintain long-term access while avoiding detection.

All infected systems must be reimaged, credentials reset, and defensive controls updated to prevent recurrence.

## Recommendations
1. Remove Scheduled Task UpdateHealthTelemetry
2. Delete Registry Entry under HKCU\...\Run
3. Purge Malware File BitSentinelCore.exe
4. Review LNK files and disable recent document execution via GPO if possible
5. Monitor for misuse of csc.exe, PowerShell, and schtasks.exe in telemetry

### Appendix

Report Compiled by: Luka Groff  
Scenario: Acme Corp - Phantom Hackers APT Intrusion

# 🎯 Threat-Hunting-Scenario-Assistance
<img width="400" src="https://github.com/user-attachments/assets/28be6b88-82ad-4f68-ae7a-412aed543cb6" />

**Participant:** Luka Groff

**Date:** 13 November 2025

## Platforms and Languages Leveraged

**Platforms:**

* Log Analytics Workspace

**Languages/Tools:**

* Kusto Query Language (KQL) for querying device events, registry modifications, and persistence artifacts

---

 # 📖 **Scenario**

A routine support request should have ended with a reset and reassurance. Instead, the so-called “help” left behind a trail of anomalies that don’t add up.

What was framed as troubleshooting looked more like an audit of the system itself — probing, cataloging, leaving subtle traces in its wake. Actions chained together in suspicious sequence: first gaining a foothold, then expanding reach, then preparing to linger long after the session ended.

And just when the activity should have raised questions, a neat explanation appeared — a story planted in plain sight, designed to justify the very behavior that demanded scrutiny.

This wasn’t remote assistance. It was a misdirection.

Your mission this time is to reconstruct the timeline, connect the scattered remnants of this “support session”, and decide what was legitimate, and what was staged.

The evidence is here. The question is whether you’ll see through the story or believe it.


## Starting Point

Before you officially begin the flags, you must first determine where to start hunting. Identify where to start hunting with the following intel given: 

1. Multiple machines in the department started spawning processes originating from the download folders. This unexpected scenario occurred during the first half of October. 
2. Several machines were found to share the same types of files — similar executables, naming patterns, and other traits.
3. Common keywords among the discovered files included “desk,” “help,” “support,” and “tool.”
4. Intern operated machines seem to be affected to certain degree.

🕵️ **Identify the most suspicious machine based on the given conditions**

Query used:
```
DeviceProcessEvents
| where ProcessCommandLine has_any ("Downloads", "desk", "help", "support", "tool") or InitiatingProcessCommandLine has_any ("Downloads", "desk", "help", "support", "tool")
| where DeviceName contains "intern"
| summarize count() by DeviceName
```
🧠 **Thought process:** The task says there are processes spawned with certain file names, so I looked into ProcessCommandLine and InitiatingProcessCommandLine to contain any of the above-mentioned words. I also looked for an "intern" account, and there was only one that really stood out

<img width="600" src="https://github.com/user-attachments/assets/1e7b2c62-12b6-4e70-86ae-71446699bcc8"/>

**Answer: gab-intern-vm**

To make sure I found the right answer I looked into the DeviceName to check for the files or commands with these words:

Query used:
```
DeviceProcessEvents
| where ProcessCommandLine has_any ("Downloads", "desk", "help", "support", "tool") or InitiatingProcessCommandLine has_any ("Downloads", "desk", "help", "support", "tool")
| where DeviceName contains "gab-intern-vm"
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine
```
and I indeed found the "SupportTool.ps1" file that has some of the words I was looking for.

<img width="800" src="https://github.com/user-attachments/assets/8aae82a1-43bc-478b-bf43-966aa057b3ec" />

---

## 🟩 Flag 1 – Initial Execution Detection

**Objective:**

Detect the earliest anomalous execution that could represent an entry point.

**What to Hunt:**

Look for atypical script or interactive command activity that deviates from normal user behavior or baseline patterns.

**Thought:**

Pinpointing the first unusual execution helps you anchor the timeline and follow the actor’s parent/child process chain.

**Hint:**

1. Downloads
2. Two

 🕵️ **What was the first CLI parameter name used during the execution of the suspicious program?**

Query used:
```
DeviceProcessEvents
| where DeviceName contains "gab-intern-vm"
| where FileName == "powershell.exe" or InitiatingProcessFileName == "powershell.exe" or FileName == "cmd.exe"
| where InitiatingProcessAccountName == "g4bri3lintern"
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId
```
🧠 **Thought process:** This one was a little tricky as I wasn't sure what the question was asking and what the answer should be, but I looked at every command that deviates from the normal use and eventually figured out that the answer was only the -ExecutionPolicy parameter, not including the rest or part of the command.

<img width="800" src="https://github.com/user-attachments/assets/a270c74e-173c-418b-b63a-df12753f58b3" />

**Answer: -ExecutionPolicy** 

---

## 🟩 Flag 2 – Defense Disabling

**Objective:**

Identify indicators that suggest attempts to imply or simulate changing security posture.

**What to Hunt:**

Search for artifact creation or short-lived process activity that contains tamper-related content or hints, without assuming an actual configuration change occurred.

**Thought:**

A planted or staged tamper indicator is a signal of intent — treat it as intent, not proof of actual mitigation changes.

**Hint:**

1. File was manually accessed

 🕵️ **What was the name of the file related to this exploit?**

Query used:
```
DeviceFileEvents
| where DeviceName contains "gab-intern-vm"
| where InitiatingProcessAccountName == "g4bri3lintern"
| where InitiatingProcessFileName contains "Explorer.EXE"
|project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath
```
🧠 **Thought process:** The thought behind it was that it has to do with a word such as defender or antivirus, or some kind of software tampering that has to do with defence. So I searched for these words in the query, and a big help was that I realized that the manual access was via explorer.exe, which really narrowed it down.

<img width="800" src="https://github.com/user-attachments/assets/c1e7ad6a-a8a8-4957-955e-cac7915b2114" />

**Answer: DefenderTamperArtifact.lnk** 

---

## 🟩 Flag 3 – Quick Data Probe

**Objective:**

Spot brief, opportunistic checks for readily available sensitive content.

**What to Hunt:**

Find short-lived actions that attempt to read transient data sources common on endpoints.

**Thought:**

Attackers look for low-effort wins first; these quick probes often precede broader reconnaissance.

**Hint:**

1. Clip

**Side Note: 1/2**

1. has query

 🕵️ **Provide the command value tied to this particular exploit**

Query used:
```
DeviceProcessEvents
| where DeviceName contains "gab-intern-vm"
| where ProcessCommandLine has_any ("clip.exe", " Get-Clipboard", "Get-Clipboard")
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp asc
```
🧠 **Thought process:** AI really helped me with this one, because I wasn't sure what the hint was saying, and I got a straight answer that it could do with a clipboard, so I looked in the right direction immediately and got an easy answer.

<img width="2048" height="121" alt="image" src="https://github.com/user-attachments/assets/ef20a267-ecb0-42c7-8759-8de20a4e3e29" />

**Answer: "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"** 

---

## 🟩 Flag 4 – Host Context Recon

**Objective:**

Find activity that gathers basic host and user context to inform follow-up actions.

**What to Hunt:**

Telemetry that shows the actor collecting environment or account details without modifying them.

**Thought:**

Context-gathering shapes attacker decisions — who, what, and where to target next.

**Hint:**

1. qwi

 🕵️ **Point out when the last recon attempt was**

Query used:
```
DeviceProcessEvents
| where DeviceName contains "gab-intern-vm"
| where ProcessCommandLine contains "qwi"
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId
```
🧠 **Thought process:** Before I start hunting the flags, I always check the ProcessCommandLine and look for suspicious-looking scripts, like whoami and other enumerating scripts, so I get the idea of the attack. I then saw the qwinsta command so it was easy to go looking for it with the given hint. 

<img width="800" src="https://github.com/user-attachments/assets/8c7e43fa-852c-4690-85c9-3a714707c887" />

**Answer: 2025-10-09T12:51:44.3425653Z** 

---

## 🟩 Flag 5 – Storage Surface Mapping

**Objective:**

Detect discovery of local or network storage locations that might hold interesting data.

**What to Hunt:**

Look for enumeration of filesystem or share surfaces and lightweight checks of available storage.

**Thought:**

Mapping where data lives is a preparatory step for collection and staging.

**Hint:**

1. Storage assessment

 🕵️ **Provide the 2nd command tied to this activity**

Query used:
```
DeviceProcessEvents
| where DeviceName contains "gab-intern-vm"
| where FileName == "powershell.exe" or InitiatingProcessFileName == "powershell.exe" or FileName == "cmd.exe"
| where InitiatingProcessAccountName == "g4bri3lintern"
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId
```
🧠 **Thought process:** Same goes for this flag, as I've already seen most of the commands initiated by the g4bri3lintern AccountName, it was quite straightforward to find the right answer.

<img width="800" src="https://github.com/user-attachments/assets/a7aba7d6-10b2-4d20-bc51-ef04400879cd" />

**Answer: "cmd.exe" /c wmic logicaldisk get name,freespace,size** 

---

## 🟩 Flag 6 – Connectivity & Name Resolution Check

**Objective:**

Identify checks that validate network reachability and name resolution.

**What to Hunt:**

Network or process events indicating DNS or interface queries and simple outward connectivity probes.

**Thought:**

Confirming egress is a necessary precondition before any attempt to move data off-host.

**Side Note: 2/2**

1. session

 🕵️ **Provide the File Name of the initiating parent process**

Query used:
```
DeviceProcessEvents
| where DeviceName contains "gab-intern-vm"
| where ProcessCommandLine has_any ("nslookup","ping","Test-NetConnection","Resolve-DnsName","tracert","traceroute","curl","Invoke-WebRequest","Invoke-RestMethod","dig")
| where InitiatingProcessAccountName == "g4bri3lintern"
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId
```
🧠 **Thought process:** I looked for all different kinds of network tests, like ping and tracert to begin with, then with the help of the internet, I added the rest of the methods and eventually found the nslookup method which gave me the answer I was looking for.

<img width="800" src="https://github.com/user-attachments/assets/1e368742-2f6d-4104-9704-20758d092b32" />

**Answer: RuntimeBroker.exe** 

---

## 🟩 Flag 7 – Interactive Session Discovery

**Objective:**

Reveal attempts to detect interactive or active user sessions on the host.

**What to Hunt:**

Signals that enumerate current session state or logged-in sessions without initiating a takeover.

**Thought:**

Knowing which sessions are active helps an actor decide whether to act immediately or wait.


 🕵️ **What is the unique ID of the initiating process**

Query used:
```
DeviceProcessEvents
| where DeviceName contains "gab-intern-vm"
| where FileName == "powershell.exe" or InitiatingProcessFileName == "powershell.exe" or FileName == "cmd.exe"
| where InitiatingProcessAccountName == "g4bri3lintern"
| project TimeGenerated, InitiatingProcessUniqueId, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId
```
🧠 **Thought process:** This was again one of those commands that I've already seen, I just had to go find the unique ID of the initiating process.

<img width="800" src="https://github.com/user-attachments/assets/af1393b0-ebf5-4f37-8657-3e6f57094e17" />

**Answer: 2533274790397065** 

---

## 🟩 Flag 8 – Runtime Application Inventory

**Objective:**

Detect enumeration of running applications and services to inform risk and opportunity.

**What to Hunt:**

Events that capture broad process/process-list snapshots or queries of running services.

**Thought:**

A process inventory shows what’s present and what to avoid or target for collection.

**Hint:**

1. Task
2. List
3. Last

 🕵️ **Provide the file name of the process that best demonstrates a runtime process enumeration event on the target host**

Query used:
```
DeviceProcessEvents
| where DeviceName contains "gab-intern-vm"
| where ProcessCommandLine has "tasklist" or FileName == "tasklist.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```
🧠 **Thought process:** With the help of the hints, I could deduce that I was looking for a tasklist in a command line, because it was also one of the commands I've previously noted.

<img width="800" src="https://github.com/user-attachments/assets/8bfae80d-8b88-42fc-abde-48bdaddc1acf" />

**Answer: tasklist.exe** 

---

## 🟩 Flag 9 – Privilege Surface Check

**Objective:**

Detect attempts to understand privileges available to the current actor.

**What to Hunt:**

Telemetry that reflects queries of group membership, token properties, or privilege listings.

**Thought:**

Privilege mapping informs whether the actor proceeds as a user or seeks elevation.

**Hint:**

1. Who

 🕵️ **Identify the timestamp of the very first attempt**

Query used:
```
DeviceProcessEvents
| where DeviceName contains "gab-intern-vm"
| where FileName == "powershell.exe" or InitiatingProcessFileName == "powershell.exe" or FileName == "cmd.exe"
| where InitiatingProcessAccountName == "g4bri3lintern"
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessParentId
```
🧠 **Thought process:** This was yet again part of the commands previously seen, so I immediately jumped to it.

<img width="800" src="https://github.com/user-attachments/assets/91eb61d0-ccfe-40c9-bbaf-c6c57812eff6" />

**Answer: 2025-10-09T12:52:14.3135459Z** 

---

## 🟩 Flag 10 – Proof-of-Access & Egress Validation

**Objective:**

Find actions that both validate outbound reachability and attempt to capture host state for exfiltration value.

**What to Hunt:**

Look for combined evidence of outbound network checks and artifacts created as proof the actor can view or collect host data.

**Thought:**

This step demonstrates both access and the potential to move meaningful data off the host...

**Side Note: 1/3**

1. support

 🕵️ **Which outbound destination was contacted first?**

Query used:
```
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where AdditionalFields != ""
|project TimeGenerated, AdditionalFields, RemoteIP, RemoteUrl
```
🧠 **Thought process:**  This flag was a bit more difficult than the rest, but I eventually started thinking rationally. First, I set the time from 9th of October 12 pm, which was just after the previous steps, and I filtered the AdditionalFields to not show if it's empty. Then it was pretty easy to see which host was contacted, but the obvious name of the host felt like it was a trap, so I evaded it for a little while until I finally gave it a shot

<img width="800" src="https://github.com/user-attachments/assets/eb2910a0-afa5-4b92-a20c-4efe91ad1a3e" />

**Answer: www.msftconnecttest.com** 

---

## 🟩 Flag 11 – Bundling / Staging Artifacts

**Objective:**

Detect consolidation of artifacts into a single location or package for transfer.

**What to Hunt:**

File system events or operations that show grouping, consolidation, or packaging of gathered items.

**Thought:**

Staging is the practical step that simplifies exfiltration and should be correlated back to prior recon.

**Hint:**

1. Include the file value


 🕵️ **Provide the full folder path value where the artifact was first dropped into**

Query used:
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where FileName has_any (".zip", ".rar", ".7z", ".tar.gz", ".cab")
| where InitiatingProcessAccountName == "g4bri3lintern"
| project TimeGenerated, ActionType, AdditionalFields, FileName, FileSize, FolderPath
```
🧠 **Thought process:** After seeing the words bundling, grouping, and packaging, I knew I was looking for a .zip type of file.

<img width="800" src="https://github.com/user-attachments/assets/d0ca1ca0-5080-4883-b069-9e956b814731" />

**Answer: C:\Users\Public\ReconArtifacts.zip** 

---

## 🟩 Flag 12 – Outbound Transfer Attempt (Simulated)

**Objective:**

Identify attempts to move data off-host or test upload capability.

**What to Hunt:**

Network events or process activity indicating outbound transfers or upload attempts, even if they fail.

**Thought:**

Succeeded or not, attempt is still proof of intent — and it reveals egress paths or block points.

**Side Note: 2/3**

1. chat

 🕵️ **Provide the IP of the last unusual outbound connection**

Query used:
```
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where AdditionalFields != ""
//| where RemoteIP == "100.29.147.161"
|project TimeGenerated, AdditionalFields, RemoteIP, ActionType
```
🧠 **Thought process:** I had to look at when the events happened before this step, so I filtered the TimeGenerated accordingly. I then filtered the AdditionalFields to contain Out (egress) and searched for the results that contain http, https, .com, .net, and others. I first found the answer, which was httpbin.org, but it connected to two different IPs. Unluckily for me, I tested the wrong IP first, which made me think that maybe it's not in fact httpbin.org. After exhausting all my options, I saw that httpbin.org was connecting to another IP, which was then correct.

 <img width="800" src="https://github.com/user-attachments/assets/d2a4034a-6ba3-4581-a796-60ce28b2838c" />

 **Answer: 100.29.147.161** 

---

## 🟩 Flag 13 – Scheduled Re-Execution Persistence

**Objective:**

Detect creation of mechanisms that ensure the actor’s tooling runs again on reuse or sign-in.

**What to Hunt:**

Process or scheduler-related events that create recurring or logon-triggered executions tied to the same actor pattern.

**Thought:**

Re-execution mechanisms are the actor’s way of surviving beyond a single session — interrupting them reduces risk.


 🕵️ **Provide the value of the task name down below**

Query used:
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| where ProcessCommandLine contains "powershell"
| project TimeGenerated, AccountName, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
```
🧠 **Thought process:** The only problem I had was figuring out what the task name is, but after careful analysis of the command, I saw the TN, which I assumed stands for task name, and I was right. I was looking for a task schedule command to begin with, and there were not many, so it was easy to find.

<img width="800" src="https://github.com/user-attachments/assets/3b0202ad-6ea3-47ad-85cf-c09e69231a73" />

 **Answer: SupportToolUpdater** 

---

## 🟩 Flag 14 – Autorun Fallback Persistence

**Objective:**

Spot lightweight autorun entries placed as backup persistence in user scope.

**What to Hunt:**

Registry or startup-area modifications that reference familiar execution patterns or repeat previously observed commands.

**Thought:**

Redundant persistence increases resilience; find the fallback to prevent easy re-entry.

**Side Note: 3/3**

1. log

⚠️ If table returned nothing: RemoteAssistUpdater

In my case, the table did in fact return nothing, so I had to use the answer provided

 **Answer: RemoteAssistUpdater** 

 ---

## 🟩 Flag 15 – Planted Narrative / Cover Artifact

**Objective:**

Identify a narrative or explanatory artifact intended to justify the activity.

**What to Hunt:**

Creation of explanatory files or user-facing artifacts near the time of suspicious operations; focus on timing and correlation rather than contents.

**Thought:**

A planted explanation is a classic misdirection. The sequence and context reveal deception more than the text itself.

**Hint:**

1. The actor opened it for some reason

 🕵️ **Identify the file name of the artifact left behind**

Query used:
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where FileName !contains "PSScriptPolicyTest"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName
```
🧠 **Thought process:** I was looking for a file, but I knew it would be impossible to find it on its own, so I had to filter for TimeGenerated again and set it from 9th of October 13:00:00 to 13:30:00. The answer was then the first file on the list, which was just after the time of the persistence step

 <img width="800" src="https://github.com/user-attachments/assets/ee9c12c7-2307-4929-bc27-cb456f6204a8" />

**Answer: SupportChat_log.lnk** 

## CONCLUSION
After completing the hunt, I realized it wasn't that hard once I started thinking like a true detective. I had to keep track of my notes, the commands, and files that I've seen along the way, and refer back to them later. The most important thing was keeping track of the time of the events, because they do follow each other and leave a trail behind.


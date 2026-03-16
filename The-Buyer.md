# Cyber Range Threat Hunt - Akira Ransomware (Advanced)



**Date of Incident:** 15 March 2026  
**Data Source:** Log Analytics workspaces, Microsoft Defender for Endpoint  

**Scope:** 3 Windows endpoints

**Analyst:** Luka Groff

---

# 🛡️ Incident Response Case Study  
## Ashford Sterling Recruitment – Akira Ransomware Investigation

This investigation reconstructs a full ransomware intrusion involving **initial access, defense evasion, credential access, reconnaissance, lateral movement, data staging, exfiltration, ransomware deployment, and anti-forensics activity**.

The attacker leveraged previously staged access to return to the environment and deploy **Akira ransomware**, resulting in file encryption and ransom demand.

---

## 🚩 Ransomware Identification

The attack was attributed to the **Akira ransomware group**, confirmed through artifacts found in the ransom note.

- **Ransomware Group:** `Akira`
- **Negotiation Portal:** `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion`
- **Victim Negotiation ID:** `813R-QWJM-XKIJ`

Encrypted files across the system were appended with the following extension:
- `.akira`

---

## 🌐 Command & Control Infrastructure

The attacker used multiple infrastructure components to download tools and maintain command and control.

### Payload Hosting

Initial tooling and malware components were downloaded from: `sync.cloud-endpoint.net`


### Malware Staging

The ransomware beacon and staging infrastructure communicated with: `cdn.cloud-endpoint.net`


This domain resolved to the following external infrastructure: 
- `104.21.30.237`
- `172.67.174.46`


### Remote Access Relay

The attacker maintained remote access using **AnyDesk relay infrastructure**: `relay-0b975d23.net.anydesk.com`

---

## 🛑 Defense Evasion

Prior to ransomware deployment, security controls were disabled using a script named: `kill.bat`

**SHA256 Hash**: `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c`

Windows Defender protections were disabled via registry tampering:
- Registry Value: `DisableAntiSpyware`

Registry modification occurred at:
- 21:03:42 UTC

---

## 🔐 Credential Access

The attacker searched for the LSASS process in order to target credentials stored in memory.

Command used: `tasklist | findstr lsass`

Credential-related activity accessed the following named pipe: `\Device\NamedPipe\lsass`

---

## 🔑 Initial Access & Persistence

The attacker returned to the environment using a **previously staged remote access tool**.

Remote access was established using: `AnyDesk`

The tool was executed from an unusual location on **AS-PC2**: `C:\Users\Public\`

---

## 🌍 Attacker Infrastructure

The external attacker IP observed controlling the session was: `88.97.164.155`

The compromised user account on AS-PC2 was: `david.mitchell`

---

## 🧭 Command & Control Deployment

A command-and-control beacon was deployed after the initial access channel became unstable.

The attacker deployed the following beacon: `wsync.exe`

Location of deployment: `C:\ProgramData\`

Two versions of the beacon were observed.

- **Original Beacon SHA256**: `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b`
- **Replacement Beacon SHA256**: `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654`


The replacement beacon was deployed after the first version failed to maintain stable communications.

---

## 🧭 Reconnaissance

The attacker deployed a network scanner to identify additional targets on the internal network.

Scanner tool: `scan.exe`

**SHA256 Hash**: `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b`

Scanner execution arguments: `/portable "C:/Users/david.mitchell/Downloads/" /lng en_us`

The scan enumerated internal hosts:
- `10.1.0.154`
- `10.1.0.183`

Attacker scanned as-pc1 and pc2 from as-srv

---

## 🔀 Lateral Movement

After reconnaissance, the attacker moved laterally to an internal server.

Authenticated account used: `as.srv.administrator`

---

## 📦 Tool Transfer

Multiple methods were used to download attacker tools.

Initial attempt used a **living-off-the-land binary (LOLBIN)**: `bitsadmin`

After the first attempt failed, the attacker switched to PowerShell: `Invoke-WebRequest`


This fallback technique allowed the attacker to successfully download additional payloads.

---

## 📂 Data Staging & Exfiltration

Prior to encryption, the attacker staged sensitive data for exfiltration.

Compression tool used: `st.exe`

**SHA256 Hash**: `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015`

Archive created: `exfil_data.zip`

---

## 💣 Ransomware Deployment

The ransomware payload was disguised as a legitimate system process: `updater.exe`

**SHA256 Hash**: `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b`

The ransomware was staged onto **AS-SRV** using: `powershell.exe`

Before encryption began, the attacker prevented recovery by deleting shadow copies: `wmic shadowcopy delete`

---

## 🧾 Ransom Note Deployment

Once encryption began, the ransomware dropped a ransom note.

Process responsible: `updater.exe`

Encryption began at: `22:18:33 UTC`

---

## 🧹 Anti-Forensics

After the ransomware executed, the attacker attempted to remove evidence of the malware.

Cleanup script: `clean.bat`

This script deleted the ransomware binary following execution.

---

## 🎯 Scope of Compromise

The following systems were confirmed compromised:
- `as-srv`
- `as-pc2`

These systems were involved in reconnaissance, lateral movement, ransomware deployment, and data staging activity.

---

## SECTION 1: RANSOM NOTE ANALYSIS [Moderate]

---

### FLAG 1 – Threat Actor
**Finding:** The ransomware family responsible for the attack was identified from the ransom note left on the compromised system. The note clearly referenced the **Akira** ransomware group, which is known for enterprise-targeted double extortion campaigns.

**Ransomware Group:**
```
Akira
```

**MITRE:** T1486 – Data Encrypted for Impact

---

### FLAG 2 – Negotiation Portal
**Finding:** The ransom note contained instructions directing victims to a TOR negotiation portal where payment instructions and communication with the attackers could occur.

**TOR Negotiation Address:**
```
akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion
```

**MITRE:** T1102 – Web Service (C2 over TOR infrastructure)

---

### FLAG 3 – Victim Identifier
**Finding:** Each victim of the ransomware campaign receives a unique identifier used during negotiations. This identifier allows the attackers to track victims and associate payments with the correct organization.

**Victim ID:**
```
813R-QWJM-XKIJ
```

**MITRE:** T1486 – Data Encrypted for Impact

---

### FLAG 4 – Encrypted File Extension
**Finding:** After encryption completed, files on compromised systems were renamed with a unique extension. This extension serves as an indicator of compromise for Akira ransomware infections.

**Encrypted File Extension:**
```
.akira
```

**MITRE:** T1486 – Data Encrypted for Impact

---

## SECTION 2: INFRASTRUCTURE [Moderate]

---

### FLAG 5 – Payload Domain
**Finding:** The attacker downloaded tools and malware components from external infrastructure hosted outside the victim network. This domain served as the primary payload hosting location.

**Payload Hosting Domain:**
```
sync.cloud-endpoint.net
```

**MITRE:** T1105 – Ingress Tool Transfer

---

### FLAG 6 – Ransomware Staging Domain
**Finding:** The ransomware payload communicated with staging infrastructure during deployment. This domain hosted components used during the ransomware deployment stage.

**Ransomware Staging Domain:**
```
cdn.cloud-endpoint.net
```

**MITRE:** T1105 – Ingress Tool Transfer

---

### FLAG 7 – C2 Infrastructure IPs
**Finding:** The staging infrastructure resolved to multiple external IP addresses associated with attacker-controlled infrastructure. These IPs were used during payload staging and command-and-control activity.

**C2 IP Addresses:**
```
104.21.30.237, 172.67.174.46
```

**MITRE:** T1071 – Application Layer Protocol

---

### FLAG 8 – Remote Tool Relay
**Finding:** The attacker maintained remote access through relay infrastructure used by a remote administration tool. Relay servers allowed connections without exposing the attacker’s direct IP address.

**Relay Domain Used:**
```
relay-0b975d23.net.anydesk.com
```

**MITRE:** T1219 – Remote Access Software

---

## SECTION 3: DEFENSE EVASION [Hard]

---

### FLAG 9 – Evasion Script
**Finding:** Prior to deploying ransomware, the attacker executed a script designed to disable security controls and prepare the system for malicious activity.

**Script Identified:**
```
kill.bat
```

**MITRE:** T1562.001 – Impair Defenses

---

### FLAG 10 – Evasion Script Hash
**Finding:** The evasion script used to disable security protections was identified and its SHA256 hash calculated for forensic verification.

**SHA256 Hash:**
```
0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c
```

**MITRE:** T1562.001 – Impair Defenses

---

### FLAG 11 – Registry Tampering
**Finding:** Windows Defender was disabled through modification of a security policy registry key. This allowed malicious tools and ransomware to execute without interference.

**Registry Value Modified:**
```
DisableAntiSpyware
```

**MITRE:** T1112 – Modify Registry

---

### FLAG 12 – Registry Modification Timestamp
**Finding:** The registry tampering event occurred shortly before the ransomware deployment phase.

**Timestamp (UTC):**
```
21:03:42
```

**MITRE:** T1112 – Modify Registry

---

## SECTION 4: CREDENTIAL ACCESS [Advanced]

---

### FLAG 13 – Process Enumeration
**Finding:** The attacker enumerated running processes to locate the LSASS process, which stores authentication credentials in memory.

**Command Executed:**
```
tasklist | findstr lsass
```

**MITRE:** T1057 – Process Discovery

---

### FLAG 14 – Credential Access Pipe
**Finding:** Activity targeting LSASS involved interaction with a named pipe used by the process.

**Named Pipe Accessed:**
```
\Device\NamedPipe\lsass
```

**MITRE:** T1003 – OS Credential Dumping

---

## SECTION 5: INITIAL ACCESS [Hard]

---

### FLAG 15 – Remote Access Tool
**Finding:** The attacker leveraged a pre-staged remote access tool to regain entry into the network environment.

**Remote Access Tool:**
```
AnyDesk
```

**MITRE:** T1219 – Remote Access Software

---

### FLAG 16 – Suspicious Execution Path
**Finding:** The remote access tool was executed from an unusual directory on the compromised workstation.

**Execution Path:**
```
C:\Users\Public\
```

**MITRE:** T1036 – Masquerading

---

### FLAG 17 – Attacker External IP
**Finding:** The investigation identified the external IP address used by the attacker during remote access activity.

**Attacker IP:**
```
88.97.164.155
```

**MITRE:** T1071 – Application Layer Protocol

---

### FLAG 18 – Compromised User Account
**Finding:** The attacker leveraged an existing user account to authenticate to the compromised workstation.

**Compromised User:**
```
david.mitchell
```

**MITRE:** T1078 – Valid Accounts

---

## SECTION 6: COMMAND & CONTROL [Hard]

---

### FLAG 19 – Primary Beacon
**Finding:** A command-and-control beacon was deployed after the original communication method failed.

**Beacon Filename:**
```
wsync.exe
```

**MITRE:** T1071 – Application Layer Protocol

---

### FLAG 20 – Beacon Deployment Location
**Finding:** The beacon was deployed in a system directory commonly abused by attackers to store malicious binaries.

**Beacon Directory:**
```
C:\ProgramData\
```

**MITRE:** T1105 – Ingress Tool Transfer

---

### FLAG 21 – Original Beacon Hash
**Finding:** The first beacon deployed on AS-PC2 was identified and its SHA256 hash calculated.

**SHA256 Hash:**
```
66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b
```

**MITRE:** T1071 – Application Layer Protocol

---

### FLAG 22 – Replacement Beacon Hash
**Finding:** After the first beacon failed to maintain communication, a replacement beacon was deployed.

**Replacement Beacon SHA256:**
```
0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654
```

**MITRE:** T1071 – Application Layer Protocol

---

## SECTION 7: RECONNAISSANCE [Moderate]

---

### FLAG 23 – Scanner Tool
**Finding:** The attacker deployed a network scanning utility to identify potential targets within the internal network.

**Scanner Tool:**
```
scan.exe
```

**MITRE:** T1046 – Network Service Discovery

---

### FLAG 24 – Scanner Hash
**Finding:** The SHA256 hash of the scanning tool was identified to support malware attribution and forensic tracking.

**SHA256 Hash:**
```
26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b
```

**MITRE:** T1046 – Network Service Discovery

---

### FLAG 25 – Scanner Execution Arguments
**Finding:** The scanner was executed in portable mode from the user's Downloads directory.

**Arguments Used:**
```
/portable "C:/Users/david.mitchell/Downloads/" /lng en_us
```

**MITRE:** T1046 – Network Service Discovery

---

### FLAG 26 – Network Enumeration Targets
**Finding:** The scanner identified two internal hosts during network discovery.

**Internal IPs Enumerated:**
```
10.1.0.154, 10.1.0.183
```

**MITRE:** T1046 – Network Service Discovery



---

## SECTION 8: LATERAL MOVEMENT [Hard]

---

### FLAG 27 – Lateral Movement Account
**Finding:** The attacker authenticated to an internal server using an administrative account.

**Account Used:**
```
as.srv.administrator
```

**MITRE:** T1021 – Remote Services

---

## SECTION 9: TOOL TRANSFER [Moderate]

---

### FLAG 28 – Initial Download Method
**Finding:** The attacker first attempted to download tools using a living-off-the-land binary.

**LOLBIN Used:**
```
bitsadmin
```

**MITRE:** T1105 – Ingress Tool Transfer

---

### FLAG 29 – Fallback Download Method
**Finding:** After the initial download method failed, the attacker switched to PowerShell.

**PowerShell Cmdlet:**
```
Invoke-WebRequest
```

**MITRE:** T1105 – Ingress Tool Transfer

---

## SECTION 10: EXFILTRATION [Hard]

---

### FLAG 30 – Data Staging Tool
**Finding:** The attacker compressed data prior to exfiltration using a dedicated staging tool.

**Tool Used:**
```
st.exe
```

**MITRE:** T1560 – Archive Collected Data

---

### FLAG 31 – Staging Tool Hash
**Finding:** The SHA256 hash of the staging tool was identified.

**SHA256 Hash:**
```
512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015
```

**MITRE:** T1560 – Archive Collected Data

---

### FLAG 32 – Exfiltration Archive
**Finding:** The attacker created an archive containing sensitive data before encryption began.

**Archive Created:**
```
exfil_data.zip
```

**MITRE:** T1560 – Archive Collected Data

---

## SECTION 11: RANSOMWARE DEPLOYMENT [Advanced]

---

### FLAG 33 – Ransomware Binary
**Finding:** The ransomware payload was disguised as a legitimate system process.

**Ransomware Filename:**
```
updater.exe
```

**MITRE:** T1036 – Masquerading

---

### FLAG 34 – Ransomware Hash
**Finding:** The SHA256 hash of the ransomware binary was identified for forensic tracking.

**SHA256 Hash:**
```
e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b
```

**MITRE:** T1486 – Data Encrypted for Impact

---

### FLAG 35 – Ransomware Staging Process
**Finding:** The ransomware binary was staged onto the server prior to execution using PowerShell.

**Process Used:**
```
powershell.exe
```

**MITRE:** T1105 – Ingress Tool Transfer

---

### FLAG 36 – Recovery Prevention
**Finding:** To prevent recovery of encrypted files, the attacker deleted all Windows shadow copies.

**Command Used:**
```
wmic shadowcopy delete
```

**MITRE:** T1490 – Inhibit System Recovery

---

### FLAG 37 – Ransom Note Origin
**Finding:** The ransomware process itself dropped the ransom note once encryption began.

**Process Responsible:**
```
updater.exe
```

**MITRE:** T1486 – Data Encrypted for Impact

---

### FLAG 38 – Encryption Start Time
**Finding:** Encryption activity began when the ransom note was dropped.

**Timestamp (UTC):**
```
22:18:33
```

**MITRE:** T1486 – Data Encrypted for Impact

---

## SECTION 12: ANTI-FORENSICS & SCOPE [Hard]

---

### FLAG 39 – Cleanup Script
**Finding:** After ransomware execution, the attacker used a script to delete the ransomware binary.

**Script Identified:**
```
clean.bat
```

**MITRE:** T1070 – Indicator Removal

---

### FLAG 40 – Affected Hosts
**Finding:** Investigation determined that two hosts were compromised during the attack.

**Compromised Hosts:**
```
as-srv, as-pc2
```

**MITRE:** T1021 – Remote Services

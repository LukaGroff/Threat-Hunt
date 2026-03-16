# Cyber Range Threat Hunt - Akira Ransomware (Advanced)



**Date of Incident:** 21 February 2026  
**Data Source:** Log Analytics workspaces, Microsoft Defender for Endpoint  

**Scope:** Two Windows endpoints

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

















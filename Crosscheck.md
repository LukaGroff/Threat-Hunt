# Cyber Range Threat Hunt - ❌ Crosscheck

<img width="683" height="1024" alt="image" src="https://github.com/user-attachments/assets/84ab44ce-f551-4fe8-bc96-ac3827ee2048" />


**Date of Incident:** 1 December 2025  
**Data Source:** Log Analytics workspaces  
**Scope:** Two Windows endpoints
**Analyst:** Luka Groff

---

## Executive Overview
An investigation identified unauthorized activity involving misuse of a legitimate user account across two endpoints. The actor used remote access and PowerShell-based tooling to perform system reconnaissance and access sensitive HR and compensation-related files, including employee scorecards and finalized bonus documents. Persistence was established through registry and scheduled task mechanisms, and sensitive data was staged into archives. Outbound connectivity was tested and attempted, and log-clearing activity was observed, indicating intent to evade detection. While no confirmed data exfiltration occurred, the behavior demonstrates deliberate preparation for unauthorized data transfer and represents a high-risk incident with exposure of sensitive internal information.
- **What happened (finding)**
- **Why it matters (impact)**
- **MITRE ATT&CK mapping**
- **Representative KQL used to identify the activity**

---

## Attack Timeline & Key Findings

### Initial Access
- Endpoint identified: `sys1-dept`
- Account observed: `5y51-d3p7`
- Access type: `Remote session`
- Source IP: `192.168.0.110`

### Early Reconnaissance
- Support script executed:`"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\5y51-D3p7\Downloads\PayrollSupportTool.ps1`
- First recon command: `"whoami.exe" /all`

### Sensitive Data Discovery
- First bonus-related file accessed: `BonusMatrix_Draft_v3.xlsx`
- Additional sensitive artifacts observed: `Employee scorecards`, `Performance review files`, `Approved year-end bonus documents`

### Data Staging
- Staging process ID: `2533274790396713`
- Initial archive created: `C:\Users\5y51-D3p7\Documents\Q4Candidate_Pack.zip`

### Outbound Connectivity Testing

First outbound connection attempt: 2025-12-03T06:27:31.1857946Z

Subsequent outbound attempt: 2025-12-03T07:26:28.5959592Z





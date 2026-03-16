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

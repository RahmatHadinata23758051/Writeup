# BasicQnA Forensics Challenge Writeup

## Overview
This challenge required analyzing a PCAP capture file (`challenge.pcapng`) to investigate a series of malicious activities on a vulnerable web application, including reconnaissance, command injection, and sensitive data exfiltration.

## Walkthrough

### 1. Initial Reconnaissance
Analysis of the PCAP file revealed significant HTTP and TLS traffic. Filtering for HTTP traffic identified interactions with `/admin/maintenance` and `/wp-admin/admin-ajax.php`.

### 2. Identifying Vulnerability
Inspection of HTTP POST requests to `/admin/maintenance` showed command injection attempts via the `backup_name` parameter. The requests were obfuscated with hexadecimal encoding. Decoding the payloads revealed shell commands like `cat /var/tmp/secret.txt`.

### 3. Exploitation & Data Exfiltration
By following the TCP streams of the command injection attempts, it was confirmed that the attacker executed arbitrary commands on the server. The attacker successfully read sensitive configuration and secret files (`/var/tmp/secret.txt`, `/app/static/.env`, `/app/templates/.env`), which contained a GitHub PAT (Personal Access Token).

### 4. Answering Questions

| Question | Answer |
| :--- | :--- |
| **Q1. Attacker IP, Victim IP** | 172.29.9.159,13.212.67.96 |
| **Q2. SSH service/version** | OpenSSH_10.2p1 Ubuntu-2ubuntu3.2 |
| **Q3. Reconnaissance tool** | Nmap |
| **Q4. Stream ID (admin creation)** | tcp.stream eq 4491 |
| **Q5. Temporary admin account** | support_c30cde@corpvault.local |
| **Q6. CVE** | (Answered independently) |
| **Q7. Abused parameter** | backup_name |
| **Q8. Files read for info** | /app/static/.env,/app/templates/.env |
| **Q9. GitHub ID** | Ich1ck3nPlus |

---
**Flag**: `v1t{llm_c0uld_s0lv3_th1s_ez_chall3ng3!!!}`

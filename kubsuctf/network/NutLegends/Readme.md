# CTF Writeup — Nut Legends

**Event:** [Your CTF Event Name]
**Category:** Network / Packet Tracer
**Difficulty:** Medium
**Flag:** `flag{kubstu(end_user_license_agreement)}`

---

## Challenge Description

> An anomaly has been detected in the network topology. Direct access to the target node is blocked at several layers of the OSI model. You are given an entry point (PC Cooper R.) and a single artifact — an image file. Reconstruct the access chain and capture the flag.

**Entry Point:** PC Cooper R. (`10.10.10.10`)
**Target:** Server#1 (Storage Server VLAN20)

---

## Network Topology

```
[Master_0828 Router]
       | Gig0/0
       | Fa0/24
   [Switch0]
   /         \
Fa0/1       Fa0/7
  |             |
[PC Cooper R.] [Server#1]
10.10.10.10    10.20.20.100
```

---

## Reconnaissance

### Step 1 — Identify IP Configuration (PC Cooper R.)

```
C:\> ipconfig
```

Output:
```
FastEthernet0:
  IPv4 Address: 10.10.10.10
  Subnet Mask:  255.255.255.0
  Default GW:   10.10.10.1
```

Gateway `10.10.10.1` diketahui — ini adalah router **Master_0828**.

---

### Step 2 — Inspect Router Configuration (Master_0828)

Klik Master_0828 → CLI:

```
enable
show running-config
```

Output kunci:
```
interface GigabitEthernet0/0.10
 encapsulation dot1Q 10
 ip address 10.10.10.1 255.255.255.0

interface GigabitEthernet0/0.20
 encapsulation dot1Q 20
 ip address 10.20.20.1 255.255.255.0
```

**Temuan:** Router menggunakan **inter-VLAN routing** dengan dua subinterface:
- **VLAN 10** (ADMIN): `10.10.10.0/24` → tempat PC Cooper R.
- **VLAN 20** (STORAGE): `10.20.20.0/24` → kemungkinan lokasi Server#1

---

### Step 3 — Check Switch VLAN Assignment (Switch0)

Klik Switch0 → CLI:

```
enable
show vlan brief
```

Output:
```
VLAN  Name     Status   Ports
----  -------  -------  --------------------------
1     default  active   Fa0/3-Fa0/23, Fa0/7, Gig0/1, Gig0/2
10    ADMIN    active   Fa0/1
20    STORAGE  active   Fa0/2
```

**Masalah ditemukan:** Port **Fa0/7** (terhubung ke Server#1) berada di **VLAN 1 (default)**, bukan VLAN 20!

---

## Exploitation

### Step 4 — Fix VLAN Assignment (Switch0)

Pindahkan Fa0/7 ke VLAN 20:

```
configure terminal
interface fastEthernet 0/7
switchport mode access
switchport access vlan 20
exit
do show vlan brief
```

Verifikasi:
```
VLAN  Name     Status   Ports
----  -------  -------  --------------------------
10    ADMIN    active   Fa0/1
20    STORAGE  active   Fa0/2, Fa0/7   ✅
```

### Step 5 — Verify Connectivity (PC Cooper R.)

```
C:\> ping 10.20.20.100
```

```
Reply from 10.20.20.100: bytes=32 time<1ms TTL=127  ✅
Reply from 10.20.20.100: bytes=32 time<1ms TTL=127  ✅
```

Server#1 kini reachable!

---

### Step 6 — Access Web Server

Buka **Desktop → Web Browser** di PC Cooper R.:

```
http://10.20.20.100
```

Response:
```
ACCESS GRANTED
[ SYSTEM STATUS: ENCRYPTED CONNECTION ESTABLISHED ]
[ SOURCE: PC_COOPER_R ]
[ TARGET: STORAGE_SERVER_VLAN20 ]

NOTICE: The key is archived in 'copyrights'. Search the legal directory.
```

Clue mengarahkan ke file `copyrights`.

---

### Step 7 — Access FTP Server

```
C:\> ftp 10.20.20.100
Username: cisco
Password: (kosong)
230- Logged in
```

FTP berhasil dengan kredensial `cisco / (blank password)`.

---

### Step 8 — Find the Flag

Buka halaman:

```
http://10.20.20.100/copyrights.html
```

Source HTML:
```html
<html>DOWNLOADING, INSTALLING, OR USING THE CISCO PACKET TRACER SOFTWARE 
CONSTITUTES ACCEPTANCE OF THE CISCO END USER LICENSE AGREEMENT
("EULA" https://www.cisco.com/c/en/us/about/legal/cloud-and-software/
kubstu(end_user_license_agreement) AND THE SUPPLEMENTAL END USER...
</html>
```

**Anomali ditemukan:** URL Cisco yang seharusnya berbunyi `end-user-license-agreement` diganti dengan **`kubstu(end_user_license_agreement)`** — string `kubstu` adalah sisipan yang tidak ada di URL Cisco asli.

---

## Flag

```
flag{kubstu(end_user_license_agreement)}
```

---

## Vulnerability Summary

| # | Temuan | Detail |
|---|--------|--------|
| 1 | **VLAN Misconfiguration** | Port Fa0/7 (Server#1) berada di VLAN 1 (default), bukan VLAN 20, sehingga server tidak reachable dari VLAN yang benar |
| 2 | **Weak FTP Credentials** | User `cisco` dengan password kosong memberikan akses FTP penuh (RWDNL) |
| 3 | **Flag Hidden in Plain Text** | Flag disisipkan dalam URL di halaman `copyrights.html` yang terlihat seperti teks legal biasa |

---

## Remediation

1. **Audit VLAN assignment** — pastikan setiap port switch dikonfigurasi ke VLAN yang tepat sesuai network design
2. **Enforce strong FTP credentials** — jangan gunakan password kosong; terapkan autentikasi yang kuat
3. **Jangan sembunyikan flag/secret dalam konten HTML publik** — gunakan autentikasi server-side yang proper

---

## Attack Flow

```
PC Cooper R. (10.10.10.10)
        │
        ▼
ipconfig → Gateway: 10.10.10.1
        │
        ▼
Master_0828: show run → VLAN 10 & VLAN 20 ditemukan
        │
        ▼
Switch0: show vlan brief → Fa0/7 salah VLAN (di VLAN 1)
        │
        ▼
Fix: switchport access vlan 20 pada Fa0/7
        │
        ▼
ping 10.20.20.100 → Reply ✅
        │
        ▼
http://10.20.20.100 → ACCESS GRANTED + clue "copyrights"
        │
        ▼
http://10.20.20.100/copyrights.html → kubstu(end_user_license_agreement)
        │
        ▼
flag{kubstu(end_user_license_agreement)} 🏁
```

---

## Tools Used

- **Cisco Packet Tracer** — simulasi jaringan
- **Cisco IOS CLI** — `show running-config`, `show vlan brief`, VLAN configuration
- **Packet Tracer Web Browser** — akses HTTP server
- **Packet Tracer FTP Client** — akses FTP server

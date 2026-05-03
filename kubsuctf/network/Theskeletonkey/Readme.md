# CTF Writeup — The Skeleton Key

**Event:** [Your CTF Event Name]
**Category:** Network / Packet Tracer
**Difficulty:** Medium
**Flag:** `KubSTU(gazebo_is_stronger_than_tarask)`

---

## Challenge Description

> "Listen, we've got some chaos on one of the switches. Errors keep piling up on the ports, logs are full, but because of some configuration lock I can't get through the access levels to figure out which interface is failing.
> Take a look at what's going on — I don't just need a report, I need a solution so the network stops throwing warnings. And don't even think about wiping the config!"

**Entry Point:** SW_ACCESS_1
**Target:** CORE_ROOT (Multilayer Switch0)

---

## Network Topology

```
[ADMIN-PC] ─── Fa0/3 ─┐
[STATION-XP-01] ─ Fa0/2 ─┤
[STATION-XP-02] ─ Fa0/5 ─┤── [SW_ACCESS_1] ── Gig0/1 ── [CORE_ROOT] ── Fa0/2 ── [Server-D&D]
                           │        (Switch1)                (Multilayer Switch0)
                    [Switch2] ── Laptop0
[Laptop1] (standalone)
```

---

## Reconnaissance

### Step 1 — Identify Interface Errors (SW_ACCESS_1)

```
SW_ACCESS_1# show interfaces status
```

Output kunci:
```
Fa0/2   connected   10    auto  auto  10/100BaseTX
Fa0/3   connected   10    auto  auto  10/100BaseTX
Fa0/5   connected    1    auto  auto  10/100BaseTX  ← ANOMALI
Gig0/1  connected  trunk  auto  auto  10/100BaseTX
```

**Temuan:** Fa0/5 (terhubung ke ADMIN-PC) berada di **VLAN 1** padahal seharusnya di VLAN 10 seperti port lainnya.

---

### Step 2 — Confirm Interface Resets

```
SW_ACCESS_1# show interfaces fastEthernet 0/5
```

Output kunci:
```
10 interface resets
```

**Konfirmasi:** Fa0/5 mengalami 10 interface resets — ini penyebab error dan warnings yang dimaksud soal.

---

### Step 3 — Inspect Full Configuration

```
SW_ACCESS_1# show running-config
```

Temuan dari config:
```
interface FastEthernet0/2
 switchport access vlan 10
 switchport mode access

interface FastEthernet0/3
 switchport access vlan 10
 switchport mode access
 switchport port-security mac-address sticky

interface FastEthernet0/5
 !  ← TIDAK ADA KONFIGURASI VLAN
```

**Root Cause:** Fa0/5 tidak memiliki konfigurasi `switchport access vlan 10` sehingga jatuh ke VLAN 1 (default) dan menyebabkan traffic mismatch → interface resets.

---

## Exploitation

### Step 4 — Fix VLAN Assignment & Harden Unused Ports

```
SW_ACCESS_1# configure terminal

SW_ACCESS_1(config)# interface fastEthernet 0/5
SW_ACCESS_1(config-if)# switchport mode access
SW_ACCESS_1(config-if)# switchport access vlan 10
SW_ACCESS_1(config-if)# no shutdown
SW_ACCESS_1(config-if)# exit

SW_ACCESS_1(config)# interface range fastEthernet 0/1, fastEthernet 0/4, fastEthernet 0/6 - 24, gigabitEthernet 0/2
SW_ACCESS_1(config-if-range)# shutdown
SW_ACCESS_1(config-if-range)# exit
```

Verifikasi:
```
SW_ACCESS_1(config)# do show interfaces status
```

```
Fa0/1   disabled    1   ✅
Fa0/2   connected  10   ✅
Fa0/3   connected  10   ✅
Fa0/4   disabled    1   ✅
Fa0/5   connected  10   ✅  ← FIXED
Fa0/6-24 disabled  1   ✅
Gig0/1  connected trunk ✅
Gig0/2  disabled    1   ✅
```

---

### Step 5 — Discover Hidden VLANs

```
SW_ACCESS_1(config)# do show vlan brief
```

```
VLAN  Name          Status    Ports
----  ------------  --------  ------
1     default       active    Fa0/1, Fa0/4, Fa0/6-Fa0/24, Gig0/2
10    USERS         active    Fa0/2, Fa0/3, Fa0/5
666   TRAP-ZONE     active
999   SECRET_D&D    active    ← MENCURIGAKAN!
```

**Temuan kritis:**
- **VLAN 666** `TRAP-ZONE` → digunakan sebagai native VLAN pada trunk (teknik anti VLAN hopping)
- **VLAN 999** `SECRET_D&D` → tidak ada port yang assigned, tapi VLAN ini exist → kemungkinan besar tempat flag disembunyikan

---

### Step 6 — Attempt Access to CORE_ROOT (Multilayer Switch0)

```
CORE_ROOT> enable
Password: [gagal]
% Bad secrets
```

Password tidak diketahui. Namun ada **banner login** yang muncul:

```
*******************************************************************************
*                                                                             *
*       [DD_LAB SECURE GATEWAY - SYSTEM VERSION 2.6.0-RELEASE]               *
*       UNAUTHORIZED ACCESS IS STRICTLY PROHIBITED.                           *
*                                                                             *
*  SESSION_ENCRYPTION_SALT [V.2]:                                             *
*  ZDIwX1NhbHRvTmF6YWQ=                                                      *
*                                                                             *
*  HINT: The salt is the key to your elevation. Decode to gain access.        *
*                                                                             *
*******************************************************************************
```

**String mencurigakan:** `ZDIwX1NhbHRvTmF6YWQ=` — format Base64!

---

### Step 7 — Decode the Salt (Base64)

```bash
echo "ZDIwX1NhbHRvTmF6YWQ=" | base64 -d
```

Output:
```
d20_SaltoNazad
```

**Password enable CORE_ROOT = `d20_SaltoNazad`**

---

### Step 8 — Access CORE_ROOT & Find the Flag

```
CORE_ROOT> enable
Password: d20_SaltoNazad
CORE_ROOT#
```

```
CORE_ROOT# show running-config
```

Di dalam config, tersembunyi di description interface:

```
interface FastEthernet0/15
 description "SECRET_PROJECT_FLAG_INSIDE: KubSTU(gazebo_is_stronger_than_tarask)"
 shutdown
```

---

## Flag

```
KubSTU(gazebo_is_stronger_than_tarask)
```

---

## Vulnerability Summary

| # | Temuan | Detail |
|---|--------|--------|
| 1 | **VLAN Misconfiguration** | Fa0/5 tidak dikonfigurasi ke VLAN 10, menyebabkan 10 interface resets dan warnings terus-menerus |
| 2 | **Credential Exposed in Banner** | Password enable diencode Base64 dan ditampilkan di banner login — trivially reversible |
| 3 | **Flag in Interface Description** | Flag disembunyikan di field `description` interface Fa0/15 yang di-shutdown |
| 4 | **No Password Encryption** | Config menggunakan `no service password-encryption` sehingga credential tidak terenkripsi |

---

## Remediation

1. **Audit semua port switch** — pastikan setiap access port dikonfigurasi ke VLAN yang tepat
2. **Jangan expose credential di banner** — Base64 bukan enkripsi, gunakan autentikasi RADIUS/TACACS+
3. **Aktifkan `service password-encryption`** — minimal obfuscate credential di running-config
4. **Shutdown semua unused ports** — kurangi attack surface
5. **Gunakan `enable secret`** dengan password yang kuat dan tidak disimpan di banner

---

## Attack Flow

```
SW_ACCESS_1: show interfaces status
        │
        ▼
Fa0/5 connected di VLAN 1 (harusnya VLAN 10) → 10 interface resets
        │
        ▼
Fix: switchport access vlan 10 pada Fa0/5
Harden: shutdown semua unused ports
        │
        ▼
show vlan brief → VLAN 999 SECRET_D&D ditemukan
        │
        ▼
CORE_ROOT: enable → % Bad secrets (password unknown)
        │
        ▼
Banner login → Base64: ZDIwX1NhbHRvTmF6YWQ=
        │
        ▼
Decode Base64 → d20_SaltoNazad
        │
        ▼
CORE_ROOT# enable → Password: d20_SaltoNazad ✅
        │
        ▼
show running-config → Fa0/15 description berisi flag
        │
        ▼
KubSTU(gazebo_is_stronger_than_tarask) 🏁
```

---

## Tools Used

- **Cisco Packet Tracer** — simulasi jaringan
- **Cisco IOS CLI** — `show interfaces status`, `show vlan brief`, `show running-config`, VLAN & port configuration
- **Base64 decode** — `echo "..." | base64 -d` untuk decode password dari banner

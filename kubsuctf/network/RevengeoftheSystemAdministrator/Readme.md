# CTF Writeup — Revenge of the System Administrator

**Event:** KubSU CTF
**Category:** Network / Packet Tracer
**Difficulty:** Medium
**Flag:** `kubstu{school_sallary_suck}`

---

## Challenge Description

> At an ordinary school, a scandal is brewing. The system administrator, who worked for just under a year for pennies, suddenly quit, leaving behind a strange note: "If you think that saving on my nerves will benefit the school — check your accounts. I left the door open for those who know how to look." The principal is in a panic: the accounting department says that access to the server with financial reports is blocked and all passwords have been changed. You are an invited cybersecurity specialist. Your task is to penetrate the school's network, reconstruct the chain of events, and find evidence of embezzlement.

**Entry Point:** PC Sysadmin (PC1/PC2/PC3) — Каморка Сис.Админа
**Target:** Server C — Серверная

---

## Network Topology

```
[Учительская / Ruang Guru]          [Бухгалтерия / Akuntansi]
  PC-T1 (0.0.0.0 - IP dihapus!)      PC-A1 (192.168.10.31)
  PC-T2 (192.168.10.12)               PC-A2 (192.168.10.33)
  PC-T3 (192.168.10.13)
          |                                    |
          └──────────────┬─────────────────────┘
                         |
                   [SchoolSwitch1]  ── Fa0/7 ──  [Server C]
                         |                       192.168.10.254
          ┌──────────────┘
[Каморка Сис.Админа / Ruang Sysadmin]
  PC1 (192.168.10.21)
  PC2 (192.168.10.22)
  PC3 (192.168.10.23)
```

---

## Reconnaissance

### Step 1 — Identifikasi IP dari PC Sysadmin

```
C:\> ipconfig
```

Output PC1:
```
IPv4 Address: 192.168.10.21
Subnet Mask:  255.255.255.0
Default Gateway: 0.0.0.0
```

Seluruh PC di subnet `192.168.10.0/24`. Server C ditemukan di `192.168.10.254`.

---

### Step 2 — Cek Konektivitas ke Server

```
C:\> ping 192.168.10.254
```

```
Reply from 192.168.10.254: bytes=32 time<1ms TTL=128  ✅
```

Server reachable dari PC sysadmin. Namun dari PC guru (PC-T1) — **tidak bisa ping** karena IP-nya dihapus sysadmin (`0.0.0.0`).

---

### Step 3 — Attempt Enable pada SchoolSwitch1

```
SchoolSwitch1> enable
Password: [gagal berkali-kali]
% Bad secrets
```

Password switch telah diubah oleh sysadmin — **"configuration lock"** yang dimaksud soal.

---

### Step 4 — Investigasi Server C

**FTP Access:**
```
C:\> ftp 192.168.10.254
Username: cisco
Password: cisco
230- Logged in ✅
```

FTP berhasil dengan kredensial default `cisco/cisco` — inilah **"the door open"** yang dimaksud sysadmin.

Namun semua file di FTP hanyalah firmware `.bin` default Packet Tracer — tidak ada file mencurigakan.

**HTTP Access:**
```
http://192.168.10.254
```

Halaman default Cisco Packet Tracer — tidak ada konten tersembunyi.

---

### Step 5 — Bypass Password Switch (Password Recovery)

Boot log SchoolSwitch1 menampilkan:
```
The password-recovery mechanism is enabled.
```

Setelah berbagai percobaan password, switch akhirnya bisa diakses. Password enable ditemukan di running-config:

```
SchoolSwitch1# show running-config
```

```
enable password SuperKrutoiPassword1337
```

---

## Exploitation

### Step 6 — Investigasi Running Config Switch

```
SchoolSwitch1# show running-config
```

Output kunci:
```
interface FastEthernet0/1
 description KubSTU(school_sallary_suck)
```

**Temuan:** Flag tersembunyi di field `description` interface Fa0/1 — namun format submission yang benar adalah lowercase:

```
kubstu{school_sallary_suck}
```

---

### Step 7 — Rekonstruksi Chain of Events (Bukti Penggelapan)

Dari investigasi ditemukan bahwa sysadmin melakukan sabotase berikut sebelum keluar:

| Aksi Sysadmin | Dampak |
|---|---|
| Mengubah enable password switch | Admin tidak bisa konfigurasi network |
| Menghapus IP PC-T1 (Ruang Guru) | Guru tidak bisa akses server |
| Membiarkan FTP `cisco/cisco` terbuka | "The door open for those who know how to look" |
| Menyembunyikan flag di description interface | Bukti tersembunyi tapi bisa ditemukan via forensik config |

---

## Flag

```
kubstu{school_sallary_suck}
```

---

## Vulnerability Summary

| # | Temuan | Detail |
|---|--------|--------|
| 1 | **Weak FTP Credentials** | FTP server menggunakan `cisco/cisco` — credential default yang tidak pernah diubah |
| 2 | **No Enable Secret** | Switch menggunakan `enable password` (plaintext) bukan `enable secret` (MD5 hash) |
| 3 | **No service password-encryption** | Semua password tersimpan plaintext di running-config |
| 4 | **Insider Threat** | Sysadmin dengan akses penuh dapat sabotase network tanpa kontrol/audit |
| 5 | **PC-T1 IP Dihapus** | Sysadmin menghapus konfigurasi IP PC guru untuk memblokir akses server |

---

## Remediation

1. **Terapkan principle of least privilege** — sysadmin tidak perlu akses ke semua device sekaligus
2. **Gunakan `enable secret`** bukan `enable password` dan aktifkan `service password-encryption`
3. **Ganti semua default credential** — FTP `cisco/cisco` adalah credential yang wajib diganti
4. **Aktifkan logging dan audit** — semua perubahan konfigurasi harus tercatat dan di-review
5. **Backup konfigurasi rutin** — simpan startup-config agar mudah recovery saat sabotase
6. **Pisahkan akses** — gunakan AAA server (RADIUS/TACACS+) agar credential tidak terpusat di device

---

## Attack Flow

```
PC Sysadmin (192.168.10.21)
        │
        ▼
ipconfig → Network: 192.168.10.0/24
        │
        ▼
ping 192.168.10.254 → Server C reachable ✅
        │
        ▼
SchoolSwitch1: enable → % Bad secrets (password diubah sysadmin)
        │
        ▼
Password recovery → enable password: SuperKrutoiPassword1337
        │
        ▼
show running-config → Fa0/1 description berisi flag
        │
        ▼
Temuan tambahan: PC-T1 IP dihapus, FTP pakai cisco/cisco
        │
        ▼
kubstu{school_sallary_suck} 🏁
```

---

## Tools Used

- **Cisco Packet Tracer** — simulasi jaringan
- **Cisco IOS CLI** — `show running-config`, `enable`, investigasi switch config
- **Packet Tracer Command Prompt** — `ipconfig`, `ping`, `ftp`
- **Packet Tracer Web Browser** — akses HTTP server

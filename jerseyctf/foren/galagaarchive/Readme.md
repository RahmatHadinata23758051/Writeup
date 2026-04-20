# CTF Writeup — Galaga Archive

**Event:** JerseyCTF  
**Category:** Forensics / Network Forensics  
**Difficulty:** Medium  
**Flag:** `jctf{roasted_galatic_invaders}`

---

## Challenge Description

> I heard rumors that there has been work on a second sequel to the original 1980's Galaga game! I was able to listen to some activity on their network, but it looks like I needed some authentication to reach the shared archive.

**File:** `galaga_galaxy_invaders2.pcap`

---

## Reconnaissance

### Step 1 — Basic File Analysis

```bash
file galaga_galaxy_invaders2.pcap
# -> pcap capture file
```

Karena artefaknya PCAP, fokus utama langsung ke analisis protokol dan stream.

### Step 2 — Protocol Triage

```bash
tshark -r galaga_galaxy_invaders2.pcap -q -z io,phs
```

Protokol dominan:
- SMB2 (akses file share)
- Kerberos (autentikasi AD)
- LDAP (directory query)
- DNS

Ini cocok dengan narasi challenge: butuh autentikasi untuk masuk shared archive.

### Step 3 — Enumerasi Akses SMB

```bash
tshark -r galaga_galaxy_invaders2.pcap --export-objects smb,extracted
ls extracted
```

Didapat file penting:
- `galatic_galaga_sequel.txt`
- `ideas1.txt`
- `ideas2.txt`
- `Shareholder_Meeting_Linkedin_POST.txt`

Isi `galatic_galaga_sequel.txt` memberi clue enkripsi:
- pesan di-XOR berulang menggunakan `SHA256(password)`
- password berasal dari akun *tech developer*

---

## Exploitation

### Step 4 — Ambil Kredensial dari Kerberos (AS-REP Roasting)

Di trafik Kerberos terlihat user domain yang bisa di-*roast* (`galatic`). Lalu diekstrak ke format hashcat mode 18200 dan di-crack pakai rockyou:

```bash
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

Password yang berhasil didapat:

```text
galagalogz
```

### Step 5 — Dekripsi `ideas1.txt`

Pakai rumus dari clue:
- key stream = `SHA256(password)`
- ciphertext di-XOR berulang dengan key stream

Hasil `ideas1.txt` jadi plaintext valid (update internal dev note), jadi metode dan password benar.

### Step 6 — Dekripsi `ideas2.txt` + Sinkronisasi Offset

`ideas2.txt` awalnya belum langsung kebaca pada offset default. Setelah diuji rotasi offset key 0..31, offset `10` menghasilkan plaintext jelas dan memuat flag:

```text
... jctf{roasted_galatic_invaders}
```

---

## Flag

```text
jctf{roasted_galatic_invaders}
```

---

## Vulnerability Summary

| # | Technique | Detail |
|---|---|---|
| 1 | **Network Artifact Leakage** | File sensitif dibagikan lewat SMB dan bisa diekstrak dari PCAP |
| 2 | **Weak Kerberos Exposure** | Akun dapat di-AS-REP roast dan password berhasil di-crack |
| 3 | **Custom Crypto Misuse** | XOR stream berbasis SHA256(password) tanpa proteksi tambahan |

---

## Tools Used

- `tshark` — parsing traffic, export SMB objects
- `hashcat` — crack AS-REP hash
- Python — dekripsi XOR berbasis SHA256

---

## Attack Flow

```text
galaga_galaxy_invaders2.pcap
          |
          v
tshark export SMB objects
          |
          v
found clues + encrypted blobs (ideas1/ideas2)
          |
          v
AS-REP roast -> crack password (galagalogz)
          |
          v
XOR decrypt with SHA256(password)
          |
          v
offset sync on ideas2 (offset 10)
          |
          v
jctf{roasted_galatic_invaders}
```

---

## Installation

```bash
# wajib: tshark + python3
# optional (kalau mau ulang full dari hash): hashcat + rockyou

python3 solve.py galaga_galaxy_invaders2.pcap
```

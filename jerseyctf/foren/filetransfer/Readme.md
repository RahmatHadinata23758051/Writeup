# CTF Writeup — file-transfer

**Event:** JerseyCTF  
**Category:** Forensics / Network Forensics  
**Difficulty:** Medium  
**Flag:** `jctf{Dah914znHQigIolS-j7xvL5XiYooM4Uce}`

---

## Challenge Description

> Our network security solution has alerted us to some suspicious traffic from a user's workstation. Can you help us figure out what is going on?  
> This is the 3rd time this month something happened with this user, we really need to improve our password policies...

**File:** `export.pcap` (PCAP network capture, 109 packets)

---

## Reconnaissance

### Step 1 — Basic File Analysis

```bash
file export.pcap
# → pcap capture file, Ethernet

capinfos export.pcap
# → 109 packets, duration ~13.56s
```

### Step 2 — Protocol Triage

```bash
tshark -r export.pcap -q -z io,phs
```

Traffic didominasi SMB/SMB2, dengan banyak paket SMB3 terenkripsi.

### Step 3 — Quick String Checks

```bash
strings -n 6 export.pcap | grep -Ei 'flag|ctf|password|user|login'
```

Tidak ada flag langsung. Maka analisis lanjut dilakukan di layer autentikasi dan stream terenkripsi.

---

## Exploitation

### Step 4 — Extract NTLMv2 Auth Data

Dari SMB Session Setup terlihat user:
- `IT640\operator1`

Hash NTLMv2 diekstrak dari traffic dan diformat untuk cracking.

### Step 5 — Crack Weak Password

```bash
hashcat -m 5600 -a 0 ntlmv2_hash.txt /usr/share/wordlists/rockyou.txt
```

Hasil:
- Password user `operator1` = `password`

Ini cocok dengan hint challenge soal kebijakan password buruk.

### Step 6 — Decrypt SMB3 and Export Transferred File

Dengan password cleartext, dekripsi SMB3 bisa dilakukan di tshark:

```bash
tshark -r export.pcap -o ntlmssp.nt_password:password -T fields -e frame.number -e _ws.col.Info
```

Terlihat file yang di-upload ke share SMB:
- `DaVinci.exe`

Ekstraksi objek SMB:

```bash
tshark -r export.pcap -o ntlmssp.nt_password:password --export-objects smb,extracted
```

Hasil: `extracted/%5cDaVinci.exe`

### Step 7 — Reverse Malware Command Channel

Dari string dan disassembly `DaVinci.exe` ditemukan:
- C2 endpoint: `10.1.2.211:55544`
- Sequence command: `CMD-SEQ-A`, `CMD-SEQ-B`, `CMD-SEQ-C`, `CMD-SEQ-D`
- XOR key hardcoded: `sorry_im_not_the_flag_:)`

Stream TCP C2 diambil dari `tcp.stream==0`, lalu payload server didekode XOR berulang dengan key di atas.

### Step 8 — Recover Final Command and Flag

Hasil decode command ketiga berisi:
- pembuatan file `C:\Users\Public\Desktop\pwnd.txt`
- command `echo` yang menyisipkan flag

Flag terbaca langsung di payload terdekripsi.

---

## Flag

```text
jctf{Dah914znHQigIolS-j7xvL5XiYooM4Uce}
```

---

## Vulnerability Summary

| # | Technique | Detail |
|---|---|---|
| 1 | **Weak Password Policy** | User memakai password lemah (`password`) dan bisa di-crack dari NetNTLMv2 |
| 2 | **SMB3 Decryption via NTLM Password** | Setelah password diketahui, encrypted SMB session dapat dianalisis |
| 3 | **XOR Obfuscation** | Payload C2 hanya di-obfuscate XOR dengan key statis, mudah dipulihkan dari binary |

---

## Tools Used

- `tshark` — protocol triage, stream inspection, SMB object extraction
- `hashcat` — cracking NetNTLMv2
- `r2` / `rabin2` / `strings` — reverse engineering `DaVinci.exe`
- Python — decoding XOR payload dan ekstraksi flag

---

## Attack Flow

```text
export.pcap
    │
    ▼
SMB2/SMB3 traffic analysis
    │
    ▼
Extract NTLMv2 auth material
    │
    ▼
Crack password (operator1:password)
    │
    ▼
Decrypt SMB3 + export DaVinci.exe
    │
    ▼
Reverse C2 protocol + XOR key recovery
    │
    ▼
Decode C2 response payload
    │
    ▼
jctf{Dah914znHQigIolS-j7xvL5XiYooM4Uce}
```

---

## Installation

```bash
# Dependencies (umumnya sudah ada di Kali/CTF VM)
sudo apt update
sudo apt install -y tshark hashcat radare2

# Jalankan solver
python3 solve.py export.pcap
```

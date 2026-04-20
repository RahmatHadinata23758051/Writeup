# CTF Writeup — Neptune Authority

**Event:** JerseyCTF  
**Category:** Forensics / Network Forensics  
**Difficulty:** Medium  
**Flag:** `jctf{48173926}`

---

## Challenge Description

> A network capture from Neptune's orbital defense perimeter shows the system entering escalation mode after the relay network reawakened. A shutdown authorization was transmitted over an encrypted channel before the perimeter locked down. Recover the materials needed to decrypt the exchange and stop the quarantine from closing around you.

**File:** `neptune-defense.pcap` (264 KB)

---

## Reconnaissance

### Step 1 — Basic File Analysis

```bash
file neptune-defense.pcap
# -> pcap capture file (Ethernet)

capinfos neptune-defense.pcap
# -> 1733 packets, durasi ~151 detik
```

### Step 2 — Protocol Triage

```bash
tshark -r neptune-defense.pcap -q -z io,phs
```

Protokol utama yang muncul:
- `http` (trafik ke `10.20.0.99:8080`)
- `tls` (trafik ke `10.20.0.50:8443`)
- `icmp` heartbeat/ping berkala

### Step 3 — Cari Artefak HTTP Penting

```bash
tshark -r neptune-defense.pcap -Y "http.request" -T fields -e frame.number -e tcp.stream -e http.request.uri
```

Ditemukan request menarik:
- `/ods.crt.enc`
- `/ods.key.enc`

Keduanya di-download dari server internal `10.20.0.99:8080`.

---

## Exploitation

### Step 4 — Export Object HTTP

```bash
tshark -r neptune-defense.pcap --export-objects http,http_objects
file http_objects/ods.crt.enc http_objects/ods.key.enc
```

Hasil:
- `ods.crt.enc` -> OpenSSL encrypted blob
- `ods.key.enc` -> OpenSSL encrypted blob

Jadi challenge ini butuh dekripsi material TLS dulu.

### Step 5 — Ambil Password Enkripsi

Saat inspeksi response HTTP `200` untuk kedua file itu, ada header custom:

```http
X-Orbit-Note: oldorbit
```

Header ini dipakai sebagai passphrase file enkripsi.

### Step 6 — Dekripsi Certificate + Private Key

```bash
openssl enc -d -aes-256-cbc -in http_objects/ods.crt.enc -pass pass:oldorbit -out ods.crt
openssl enc -d -aes-256-cbc -in http_objects/ods.key.enc -pass pass:oldorbit -out ods.key
```

Output:
- `ods.crt` -> PEM certificate
- `ods.key` -> RSA private key

### Step 7 — Dekripsi Channel TLS 8443

```bash
tshark -r neptune-defense.pcap \
  -o "tls.keys_list:10.20.0.50,8443,http,ods.key" \
  -o "tls.debug_file:tlsdebug.txt" \
  -Y "tcp.stream==71"
```

Dari TLS plaintext/debug, muncul response HTTP yang berisi:

```text
STATUS: ESCALATION_ACTIVE
COUNTDOWN: ACTIVE
SHUTDOWN_CODE: 48173926
```

Nilai `SHUTDOWN_CODE` adalah komponen flag.

---

## Flag

```text
jctf{48173926}
```

---

## Vulnerability Summary

| # | Technique | Detail |
|---|---|---|
| 1 | HTTP Object Recovery | Mengambil file terenkripsi dari PCAP (`ods.crt.enc`, `ods.key.enc`) |
| 2 | Key Material Recovery | Password bocor di header HTTP (`X-Orbit-Note: oldorbit`) |
| 3 | TLS Decryption | Private key dipakai untuk decrypt TLS stream 8443 |
| 4 | Sensitive Data Exposure | Kode shutdown terkirim jelas di HTTP response dalam sesi TLS terdekripsi |

---

## Tools Used

- `tshark` — analisis PCAP, export object, decrypt TLS
- `openssl` — dekripsi blob OpenSSL (`enc`)
- Python (`solve.py`) — automasi end-to-end extraction

---

## Attack Flow

```text
neptune-defense.pcap
      |
      +--> HTTP object export
      |      |
      |      +--> ods.crt.enc + ods.key.enc
      |      |
      |      +--> X-Orbit-Note: oldorbit
      |             |
      |             +--> decrypt cert/key via openssl
      |
      +--> TLS stream 10.20.0.50:8443
             |
             +--> decrypt with ods.key
                    |
                    +--> SHUTDOWN_CODE: 48173926
                           |
                           +--> jctf{48173926}
```

---

## Installation

```bash
# Debian/Ubuntu/Kali
sudo apt update
sudo apt install -y tshark openssl python3

# Run solver
python3 solve.py
```

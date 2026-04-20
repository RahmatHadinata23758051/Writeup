# CTF Writeup — how-do-i-write

**Event:** JerseyCTF  
**Category:** Web / ICS  
**Difficulty:** Medium  
**Flag:** `jctf{VQsLCvjzdo2W8Rq0-9MDzvkvUmlI88qfM3xKfUcs2YqmEvXV-zv9oSlQIJ17dxyXaD}`

---

## Challenge Description

> We're trying to collect some debug information from our ventilation systems. Unfortunately the company that made them has since gone out of business. All we have is this old copy of a service manual. Are you able to get us the information we need?
>
> NOTE: Due to our method of sandboxing, a new instance of this challenge is spawned for every TCP connection. Make sure your payload uses a persistent connection.

**URL:** `http://how-do-i-write.aws.jerseyctf.com`

---

## Reconnaissance

### Step 1 — Bypass Login via Client-Side Check

Halaman awal meminta login. Setelah lihat `login.js`, validasi credential ternyata full di client-side:

```javascript
["b3BlcmF0b3IxOnBhc3N3b3Jk","b3BlcmF0b3IyOnBhc3N3b3Jk"].indexOf(btoa(username+":"+password))>-1
  ? window.location.replace("/index.php?authorized=1")
  : alert("INVALID CREDENTIALS")
```

Artinya kita bisa langsung akses:

```bash
http://how-do-i-write.aws.jerseyctf.com/index.php?authorized=1
```

Tidak ada server-side auth beneran untuk endpoint API/raw.

### Step 2 — Inspect JavaScript (Hint)

Di halaman utama ada `hvac.js`. Dari file ini kelihatan dua jalur komunikasi:

1. `api.php?op=...` untuk operasi normal (get temp, get fanspeed, set setpoint, dll)
2. `raw.php` untuk request binary low-level (Modbus-like frame)

Potongan penting:

```javascript
function p(unit,payload,cb){
  ...
  xhr.open("POST","raw.php",true)
  xhr.setRequestHeader("Content-Type","application/octet-stream")
}
```

Dan ada helper function code:
- `0x01` read coils
- `0x02` read discrete inputs
- `0x03` read holding regs
- `0x04` read input regs

### Step 3 — Analyze Service Manual PDF

Dari `manual.pdf` (OCR), bagian paling penting:

- **Coil `00062` = Debug Bit**
- **Input Registers `30031..30050` = System Messages**
- Saat debug bit = 1, area message diisi debug information
- Catatan: `api.php` dan web panel **tidak bisa toggle debug bit**

Ini jadi jalur eksploitasi utama: pakai `raw.php` untuk set coil debug.

---

## Exploitation

### Step 4 — Map Register Addressing

`hvac.js` manggil read input register untuk message pakai address `30` panjang `20`.

Kenapa? Karena mapping Modbus biasanya:
- 30031 (manual) -> address zero-based `30`
- total 20 register = 30031..30050

### Step 5 — Toggle Debug Bit via Raw Modbus Write

Gunakan function `0x05` (Write Single Coil):
- Coil 00062 -> address `61`
- ON value `0xFF00`

Frame dibuat seperti di `hvac.js` (MBAP + PDU), dikirim ke `POST /raw.php`.

### Step 6 — Critical Requirement: Persistent TCP Connection

Ini bagian yang paling bikin jebakan challenge.

Server spawn instance baru setiap TCP koneksi baru. Jadi kalau:
- request 1: set debug
- request 2: read message

...tapi dilakukan pakai dua koneksi berbeda, state debug hilang karena request kedua masuk instance baru.

Solusinya: kirim semua request dalam **satu koneksi HTTP keep-alive** ke `raw.php`.

### Step 7 — Dump Debug Messages from Unit 1 and Unit 2

Setelah debug bit ON:
- Unit 1 message berisi prefix `P1:` + setengah flag
- Unit 2 message berisi prefix `P2:` + setengah flag

Contoh output solver:

```text
[+] Unit 1: P1: jctf{VQsLCvjzdo2W8Rq0-9MDzvkvUmlI88q
[+] Unit 2: P2: fM3xKfUcs2YqmEvXV-zv9oSlQIJ17dxyXaD}
[+] Flag: jctf{VQsLCvjzdo2W8Rq0-9MDzvkvUmlI88qfM3xKfUcs2YqmEvXV-zv9oSlQIJ17dxyXaD}
```

---

## Solver

File: `solver.py`

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
cd /home/nata/jerseyctf/web/how-do-i-write
./solver.py
```

Inti logic solver:
1. Buka 1 socket ke host target
2. Kirim POST binary ke `raw.php` dengan header `Connection: keep-alive`
3. `unit=1`: write coil 61 = ON, lalu read input regs 30..49
4. `unit=2`: write coil 61 = ON, lalu read input regs 30..49
5. Ekstrak string setelah `P1:` dan `P2:`, gabungkan jadi flag

---

## Vulnerability Summary

| # | Vulnerability | Detail |
|---|---|---|
| 1 | **Client-side authorization bypass** | Login validasi dilakukan di JavaScript, bukan di server |
| 2 | **Unsafe low-level endpoint exposure** | `raw.php` bisa diakses langsung dan menerima command Modbus write |
| 3 | **Privilege boundary broken by protocol path** | Web/API sengaja blok toggle debug, tapi raw backend tetap mengizinkan |
| 4 | **State tied to connection lifecycle** | Sandbox per-TCP connection bisa dieksploitasi kalau attacker paham keep-alive |

---

## Remediation

1. Pindahkan auth sepenuhnya ke server-side session/token validation
2. Lindungi `raw.php` dengan auth + authorization ketat (bukan public endpoint)
3. Batasi function code yang boleh dipakai dari web tier (deny write coil/register)
4. Pisahkan jaringan management/debug channel dari user-facing app
5. Audit semua jalur akses non-UI (direct protocol bridge) sebelum production

---

## Tools Used

- `curl` — enumerasi endpoint web
- `tesseract` + `pdftoppm` — OCR manual PDF
- Python `socket` + `struct` — crafting Modbus frame dan persistent keep-alive exploit

---

## Attack Flow

```text
Inspect login.js
    │
    ▼
Bypass login with /index.php?authorized=1
    │
    ▼
Inspect hvac.js → discover raw.php binary Modbus bridge
    │
    ▼
Read manual.pdf → find Debug Bit (coil 00062) + message regs (30031..30050)
    │
    ▼
Open single persistent TCP connection
    │
    ▼
Write coil 61 (debug=1) on unit 1 and unit 2
    │
    ▼
Read input regs address 30 length 20
    │
    ▼
Get P1 + P2 and concatenate
    │
    ▼
jctf{...}
```

---

## Catatan

Flag bisa berbeda antar run karena environment challenge di-spawn ulang per koneksi TCP. Yang penting adalah metode eksploitasinya: **toggle debug + read message pada koneksi yang sama**.

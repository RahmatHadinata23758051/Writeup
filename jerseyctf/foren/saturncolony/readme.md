# CTF Writeup — Saturn Colony

**Event:** JerseyCTF  
**Category:** Forensics  
**Difficulty:** Medium  
**Flag:** `jctf{S4turn_Sh4rd_R3v3al_2026}`

---

## Challenge Description

> A remote research station designated Saturn has gone silent, but not before transmitting a full memory dump and an encrypted payload. The station ran five colony modules - mercury, venus, earth, mars, and jupiter - each holding part of a critical jump authorization key in volatile memory. Recover the fragments, reconstruct the key, and learn where the surviving route leads next.

**Artifacts:** `saturn.lime`, `payload.enc`, `iv.hex`

---

## Reconnaissance

### Step 1 — Identify Main Artifacts

Awal analisis dilakukan ke tiga artefak utama:

- `saturn.lime` → full memory dump
- `payload.enc` → ciphertext target
- `iv.hex` → IV AES

Di memory dump ditemukan proses terkait colony modules:

- `mercury`
- `venus`
- `earth`
- `mars`
- `jupiter`

Serta proses `jump_authorizer`.

### Step 2 — Validate Decoy Binary

`jump_authorizer` sempat terlihat mencetak string seperti fragment/key, tapi setelah direview binary-nya, itu hanya generator decoy (random output), bukan sumber key asli.

Artinya, fokus dipindah ke memori proses Python module.

### Step 3 — Hunt Strings Per-Module

Dump VMA per PID untuk 5 module dibandingkan secara diferensial (unique string antar-module). Dari sini muncul pola string obfuscated yang konsisten:

- Mercury: ````7?(9/(#``kuo``l>>oho8b<9n;``
- Venus: ```` ,?4/)``huo``;8n>ljjo>8kh``
- Earth: ````?;(.2``iuo``okk9kii?<8<>``
- Mars: ````7;()``nuo``?m>cm9k>8>?l``
- Jupiter: ````0/*3.?(``ouo``cl8?hm8jbcbo?8lk``

Pola ini sangat mencurigakan karena struktur antar-module mirip, hanya kontennya yang beda.

---

## Exploitation

### Step 4 — Deobfuscation

Dilakukan uji transformasi sederhana (XOR, ROT, dsb). XOR dengan `0x5A` langsung menghasilkan format yang sangat jelas:

- `::mercury::1/5::6dd525b8fc4a`
- `::venus::2/5::ab4d6005db12`
- `::earth::3/5::511c133efbfd`
- `::mars::4/5::e7d97c1dbde6`
- `::jupiter::5/5::96be27b08985eb61`

### Step 5 — Reconstruct AES Key

Gabungkan fragment sesuai urutan `i/5`:

```text
6dd525b8fc4a + ab4d6005db12 + 511c133efbfd + e7d97c1dbde6 + 96be27b08985eb61
= 6dd525b8fc4aab4d6005db12511c133efbfde7d97c1dbde696be27b08985eb61
```

Hasilnya 64 hex char = 32 byte (AES-256 key).

### Step 6 — Decrypt Payload

Mode dari challenge hint dan validasi hasil:

- Algorithm: `AES-256-CBC`
- Key: hasil gabungan 5 fragment
- IV: dari `iv.hex`
- Ciphertext: `payload.enc`

Decryption + PKCS#7 unpad menghasilkan:

```text
jctf{S4turn_Sh4rd_R3v3al_2026}
```

---

## Flag

```text
jctf{S4turn_Sh4rd_R3v3al_2026}
```

---

## Findings Summary

| # | Finding | Detail |
|---|---|---|
| 1 | Decoy Process | `jump_authorizer` hanya memproduksi output acak untuk menyesatkan |
| 2 | Memory-only Fragments | Fragmen key tidak disimpan jelas di disk, tetapi ada di volatile memory proses module |
| 3 | Lightweight Obfuscation | Fragment disamarkan dengan XOR `0x5A`, mudah dibuka setelah pola terlihat |
| 4 | Split-Key Design | Key AES-256 dipecah ke 5 module (`1/5` s.d. `5/5`) |

---

## Tools Used

- `volatility3` — process/memory triage
- `strings`, `rg` — hunting string unik
- Python — deobfuscation + key reconstruction + decryption

---

## Attack Flow

```text
Analyze memory dump (saturn.lime)
        │
        ▼
Identify 5 module processes + jump_authorizer
        │
        ▼
Discard jump_authorizer as decoy
        │
        ▼
Extract unique obfuscated strings from each module memory
        │
        ▼
XOR 0x5A -> reveal fragments ::module::i/5::<hex>
        │
        ▼
Concatenate fragments in order 1..5 -> AES-256 key
        │
        ▼
Decrypt payload.enc with AES-256-CBC + iv.hex
        │
        ▼
jctf{S4turn_Sh4rd_R3v3al_2026}
```

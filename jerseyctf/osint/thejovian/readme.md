# CTF Writeup — The Jovian Graveyard

**Event:** JerseyCTF  
**Category:** OSINT / Forensics  
**Difficulty:** Medium  
**Flag:** `jctf{H1M4L14_TH3_F0RG3_M4ST3R}`

---

## Challenge Description

> A fragmented Orion report and a damaged transcript from the Jovian system reference a forge built on one of Jupiter's moons. The forge refined Mnemosyne at industrial scale before it was lost. Identify the moon, derive the site-access key, and unlock the final harvest record.

**Files provided:**
- `OR_DIV_RES_901.txt` — Orion navigation archive fragment with data points and encryption protocol
- `JUPITER_TRANSCRIPT_FRAGMENT.log` — Recovered audio log from Black Box 09-H
- `SUCCESS_HARVEST_COMPLETE.enc` — OpenSSL-encrypted harvest record (the target)

---

## Reconnaissance

### Step 1 — Read OR_DIV_RES_901.txt

Dokumen arsip Orion menyebutkan tiga data point untuk mengidentifikasi bulan Jupiter, sekaligus format kunci enkripsi:

| Clue | Extracted Value |
|------|----------------|
| Discovery date | Late 1904 (Perrine Expedition) |
| Orbital radius | ~11,460,000 km dari pusat Jupiter |
| Classification | Anggota terbesar dari kelompok orbitalnya |
| Key format | `[MoonName]_[Year]_[DistanceKM]` |

### Step 2 — Read JUPITER_TRANSCRIPT_FRAGMENT.log

Di dalam log audio terdapat breadcrumb tersembunyi pada bagian komentar NAV-UNIT:

```
"They destroyed the Himalia Forge to stop the very progress you are now helping me restore."
```

Nama bulan langsung disebutkan: **Himalia**. Transkrip berfungsi ganda — sebagai lore dan sebagai petunjuk OSINT.

### Step 3 — Verify Moon Identity

Cross-reference semua clue dengan data bulan Jovian yang diketahui:

| Data Point | Clue | Himalia Match |
|---|---|---|
| Discovery | 1904, Perrine Expedition | Ditemukan Charles Perrine, 3 Desember 1904 ✔ |
| Orbital Radius | ~11,460,000 km | Mean orbital radius ~11,461,000 km ✔ |
| Classification | Terbesar di kelompok orbitalnya | Anggota terbesar Himalia group (prograde irregular satellites) ✔ |

Semua clue cocok → **Moon = Himalia**

---

## Exploitation

### Step 4 — Derive the Decryption Key

Menggunakan format kunci dari `OR_DIV_RES_901.txt`:

```
KEY FORMAT : [MoonName]_[Year]_[DistanceKM]
KEY        : Himalia_1904_11460000
```

### Step 5 — Identify Encryption Type

```bash
file SUCCESS_HARVEST_COMPLETE.enc
# → openssl enc'd data with salted password
```

File adalah OpenSSL symmetric-key encrypted blob. Gunakan `openssl enc` dengan kunci yang sudah diderivasi sebagai passphrase.

### Step 6 — Decrypt the File

```bash
openssl enc -aes-256-cbc -d -pbkdf2 \
  -pass pass:"Himalia_1904_11460000" \
  -in SUCCESS_HARVEST_COMPLETE.enc
```

Output:

```
jctf{H1M4L14_TH3_F0RG3_M4ST3R}
```

---

## Flag

```
jctf{H1M4L14_TH3_F0RG3_M4ST3R}
```

---

## Vulnerability Summary

| # | Technique | Detail |
|---|---|---|
| 1 | OSINT / Lore Analysis | Tiga clue faktual tentang bulan Himalia disembunyikan di dokumen fiksi |
| 2 | Steganographic Breadcrumb | Nama bulan bocor langsung di log transcript sebagai flavor text |
| 3 | OpenSSL AES-256-CBC | File terenkripsi dibuka menggunakan kunci yang diderivasi dengan PBKDF2 |

---

## Tools Used

- `file` — identifikasi tipe file
- `openssl` — dekripsi AES-256-CBC dengan PBKDF2
- Manual OSINT — cross-reference katalog bulan NASA/JPL

---

## Attack Flow

```
OR_DIV_RES_901.txt + JUPITER_TRANSCRIPT_FRAGMENT.log
                        │
                        ▼
        OSINT: Identifikasi Himalia
     (discovery 1904, orbital radius, group)
                        │
                        ▼
         Moon=Himalia | Year=1904 | Dist=11460000
                        │
                        ▼
          Key: Himalia_1904_11460000
                        │
                        ▼
    openssl enc -aes-256-cbc -d -pbkdf2 ...
                        │
                        ▼
        jctf{H1M4L14_TH3_F0RG3_M4ST3R}
```

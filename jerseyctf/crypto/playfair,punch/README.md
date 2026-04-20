# CTF Writeup — Play Fair, Punch!

**Event:** JerseyCTF  
**Category:** Crypto / Classical Cipher  
**Difficulty:** Medium  
**Flag:** `jctf{SAMANDMISSSAMSPACEMACAQUEMONKEYS}`

---

## Challenge Description

> The Ichikawa City Zoo has a well-kept secret regarding the lineage of their beloved rising star, Punch the Monkey. The only proof they have is this old punch card in the administrator's office. Can you figure out who it might be?

**File:** `punch-card.png`

---

## Reconnaissance

### Step 1 — Basic File Analysis

```bash
file punch-card.png
# → PNG image data
```

Challenge hanya memberikan satu gambar punch card klasik (IBM-style). Dari judul **Play Fair, Punch!**, indikasi kuat mengarah ke:
1. Data pada kartu punch (Hollerith encoding)
2. Cipher klasik Playfair

### Step 2 — Visual Pattern Recognition

Punch card berisi lubang-lubang hitam dalam grid baris/kolom. Barisnya cocok dengan layout IBM 12-row:

`12, 11, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9`

Dengan mendeteksi tiap hole sebagai pasangan `(kolom, baris)`, kita bisa decode tiap kolom menjadi karakter Hollerith.

---

## Exploitation

### Step 3 — Extract Hole Matrix (Automated)

Solver membaca gambar, lalu:
1. Konversi ke grayscale
2. Scan 80 kolom punch dengan pitch tetap
3. Untuk setiap cell, cek area inti apakah full black (`core < 40`)
4. Simpan baris yang ter-punch

Hasil decode Hollerith:

```text
OEGFDKGKRYRYOELTAGELGFPEWBFLRPLDCY
```

### Step 4 — Decode as Playfair Cipher

Dari hint judul, string di atas didekripsi sebagai Playfair dengan key:

```text
PUNCH
```

Hasil plaintext:

```text
SAMANDMISSSAMSPACEMACAQUEMONKEYS
```

String ini langsung cocok sebagai isi flag (uppercase) sesuai validasi challenge.

---

## Flag

```text
jctf{SAMANDMISSSAMSPACEMACAQUEMONKEYS}
```

---

## Vulnerability Summary

| # | Technique | Detail |
|---|---|---|
| 1 | **Hollerith / Punch Card Decoding** | Data disimpan sebagai lubang baris-kolom pada kartu punch |
| 2 | **Playfair Cipher** | Ciphertext hasil punch card didekripsi dengan key `PUNCH` |

---

## Tools Used

- Python 3
- `Pillow` + `numpy` untuk image parsing
- Script custom untuk decode Hollerith + Playfair

---

## Attack Flow

```text
punch-card.png
      │
      ▼
Extract punch holes (grid scan)
      │
      ▼
Hollerith decode
      │
      ▼
OEGFDKGKRYRYOELTAGELGFPEWBFLRPLDCY
      │
      ▼
Playfair decrypt (key = PUNCH)
      │
      ▼
SAMANDMISSSAMSPACEMACAQUEMONKEYS
      │
      ▼
jctf{SAMANDMISSSAMSPACEMACAQUEMONKEYS}
```

---

## Installation

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

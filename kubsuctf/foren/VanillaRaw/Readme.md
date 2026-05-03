# CTF Writeup — Vanilla raw

**Event:** KubSU CTF  
**Category:** Forensic  
**Difficulty:** Unknown  
**Flag:** `KubSTU{m3m0ry_unl1nk3d_tmpfs_f0r3ns1cs}`

---

## Challenge Description

> We received a RAM dump, but for some reason we can't analyze it. Help us out.

---

## Reconnaissance

### Step 1 — Identify the File

Artefak yang diberikan hanya satu file:

```bash
file memory.raw
```

Hasilnya tidak memberi informasi berarti:

```text
memory.raw: data
```

Ukuran file juga terlihat seperti dump RAM:

```bash
ls -lh memory.raw
```

```text
-rw-r--r-- 1 nata nata 2.0G memory.raw
```

Sekilas ini tampak seperti memory dump mentah, tetapi signature format normal tidak ada.

### Step 2 — Check for Obvious Data

Pengecekan awal dengan `xxd`, `strings`, dan sampling di beberapa offset menunjukkan sesuatu yang aneh: hampir seluruh isi file adalah byte nol.

Contoh:

```bash
xxd -l 64 memory.raw
```

```text
00000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

`exiftool` juga memberi petunjuk penting:

```text
Error : First 1039 MB of file is binary zeros
```

Ini menandakan file bukan dump RAM biasa yang kaya artefak, melainkan carrier yang hampir kosong.

### Step 3 — Locate the Only Non-Zero Region

Karena file 2 GB ini hampir seluruhnya nol, pendekatan terbaik adalah mencari region non-zero.

Setelah discan, ternyata hanya ada satu blok data yang benar-benar berisi:

- start: `0x3df027ed`
- end: `0x3df03088`
- size: `2204` byte

Region itu lalu diekstrak menjadi `blob.bin`.

---

## Deep Analysis

### Step 4 — Inspect the Extracted Blob

Blob hasil ekstraksi tampak seperti data acak:

```bash
file blob.bin
```

```text
blob.bin: OpenPGP Secret Key
```

Tetapi hasil ini menyesatkan. Parser umum seperti `gpg`, `openssl`, `binwalk`, dan `foremost` tidak bisa mengekstrak apa pun yang valid dari blob tersebut.

Ini berarti kemungkinan besar kita tidak berhadapan dengan file terenkripsi yang utuh, melainkan data yang harus dibaca ulang dengan susunan byte berbeda.

### Step 5 — Try Alternative Byte Layouts

Karena ukuran blob kecil dan tidak punya plaintext langsung, langkah berikutnya adalah mencoba menata ulang byte-nya.

Strategi yang berhasil adalah:

1. anggap `blob.bin` sebagai matriks byte
2. gunakan lebar 4 byte per baris
3. baca ulang data per kolom, bukan per baris

Dengan kata lain, data ditransposisikan.

Script pendek untuk mengujinya:

```python
from pathlib import Path

b = Path("blob.bin").read_bytes()
w = 4
h = len(b) // w
rows = [b[i*w:(i+1)*w] for i in range(h)]
col = bytes(rows[r][c] for c in range(w) for r in range(h))
print(col)
```

Saat hasil `col` diperiksa, flag muncul jelas di dalam output:

```text
KubSTU{m3m0ry_unl1nk3d_tmpfs_f0r3ns1cs}
```

---

## Exploitation

### Step 6 — Extract the Flag Programmatically

Supaya solve bisa direproduksi, solver cukup:

1. membaca `memory.raw`
2. mencari semua byte non-zero
3. mengekstrak region non-zero tunggal
4. menyusun ulang blob dengan lebar 4 byte
5. mencari pola `KubSTU{...}`

Solver final disimpan sebagai [`solve.py`](/home/nata/ctf/kubsuctf/foren/VanillaRaw/solve.py).

---

## Flag

```text
KubSTU{m3m0ry_unl1nk3d_tmpfs_f0r3ns1cs}
```

---

## Forensic Summary

| # | Finding | Detail |
|---|---|---|
| 1 | **Fake/Minimal Memory Dump** | `memory.raw` berukuran 2 GB tetapi hampir seluruhnya berisi byte nol |
| 2 | **Single Hidden Payload** | Hanya ada satu region non-zero sepanjang 2204 byte di offset `0x3df027ed` |
| 3 | **Byte Layout Obfuscation** | Payload tidak bisa diparse langsung karena flag disembunyikan lewat transposisi byte dengan lebar 4 |

---

## Remediation

1. **Jangan mengandalkan obfuscation sederhana** — transposisi byte hanya menyulitkan analisis dangkal, bukan proteksi nyata
2. **Gunakan format dump yang jelas** — memory image seharusnya memiliki struktur atau metadata acquisition yang konsisten
3. **Lakukan validasi artefak sebelum distribusi** — file yang tampak seperti RAM dump tetapi hampir seluruhnya nol harus segera dicurigai sebagai carrier tersembunyi

---

## Tools Used

- `file` — identifikasi awal file
- `xxd` — melihat isi biner pada offset tertentu
- `strings` — triage cepat plaintext
- Python — scanning region non-zero dan transposisi byte

---

## Attack Flow

```text
Inspect memory.raw
      |
      v
Discover file is almost entirely zero
      |
      v
Scan for non-zero region
      |
      v
Extract 2204-byte blob from 0x3df027ed
      |
      v
Try alternate interpretations of blob
      |
      v
Transpose bytes using width = 4
      |
      v
Flag appears in reconstructed output
      |
      v
KubSTU{m3m0ry_unl1nk3d_tmpfs_f0r3ns1cs}
```

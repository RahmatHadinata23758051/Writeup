# CTF Writeup — The Ancient Note

**Event:** KubsuCTF  
**Category:** Misc / Steganography  
**Difficulty:** Easy  
**Flag:** `KubSTU{h1dd3n_truth_b3tw33n}`

---

## Challenge Description

> We are given a text file `ancient_note.txt` — supposedly an ancient manuscript from an abandoned library. The text is in English, philosophical reflections on the search for hidden truth.

**Artifact:** `ancient_note.txt`

---

## Reconnaissance

### Step 1 — Inspect the File

Karena challenge hanya memberi satu file teks, langkah pertama yang paling masuk akal adalah memeriksa isi file dan karakteristik dasarnya.

Command yang dipakai:

```bash
file ancient_note.txt
sed -n '1,200p' ancient_note.txt
xxd -g 1 ancient_note.txt | sed -n '1,80p'
```

Hasil penting yang langsung terlihat:

- File bertipe UTF-8 text dengan line ending CRLF
- Saat dibuka biasa, teks terlihat seperti narasi bahasa Inggris yang normal
- Namun di output hex terlihat banyak byte `e2 80 8b` dan `e2 80 8c`

Kedua byte sequence itu adalah:

- `U+200B` → Zero Width Space
- `U+200C` → Zero Width Non-Joiner

Ini indikator kuat bahwa flag kemungkinan disisipkan lewat karakter tak terlihat.

### Step 2 — Notice the Decoy Layer

Di bagian kutipan tengah juga ada beberapa huruf yang terlihat normal tetapi sebenarnya memakai Unicode homoglyph dari alfabet Cyrillic, misalnya:

- `о` bukan `o`
- `е` bukan `e`
- `І` bukan `I`
- `і` bukan `i`

Lapisan ini tampaknya berfungsi sebagai pengalih perhatian atau petunjuk bahwa file memang memanfaatkan karakter Unicode yang sulit dilihat secara visual.

---

## Exploitation

### Step 3 — Extract the Zero-Width Characters

Setelah semua karakter zero-width dikumpulkan, dua karakter itu dipetakan menjadi bit:

- `U+200B` → `0`
- `U+200C` → `1`

Lalu bitstream dibaca per 8 bit sebagai ASCII.

Script Python singkat:

```python
from pathlib import Path

text = Path("ancient_note.txt").read_text(encoding="utf-8")
hidden = [ch for ch in text if ch in ("\u200b", "\u200c")]
bits = "".join("0" if ch == "\u200b" else "1" for ch in hidden)
flag = "".join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
print(flag)
```

Output:

```text
KubSTU{h1dd3n_truth_b3tw33n}
```

### Step 4 — Validate the Result

Hasil decode langsung membentuk format flag yang valid dan utuh:

```text
KubSTU{h1dd3n_truth_b3tw33n}
```

Tidak diperlukan brute force, reversing tambahan, ataupun asumsi manual terhadap isi flag.

---

## Flag

```text
KubSTU{h1dd3n_truth_b3tw33n}
```

---

## Vulnerability Summary

| # | Technique | Detail |
|---|---|---|
| 1 | **Zero-Width Steganography** | Flag disisipkan memakai karakter Unicode tak terlihat di antara teks biasa |
| 2 | **Unicode Obfuscation** | Homoglyph Cyrillic dipakai untuk menyamarkan adanya manipulasi karakter |
| 3 | **Visual Deception** | Secara kasat mata file tampak seperti manuskrip biasa, padahal payload tersembunyi ada di layer karakter |

---

## Remediation

1. Normalisasi Unicode saat memproses dokumen dari sumber tidak tepercaya
2. Gunakan deteksi karakter zero-width dalam pipeline inspeksi file
3. Tampilkan metadata atau representasi escaped saat melakukan audit teks sensitif

---

## Tools Used

- `file` — identifikasi tipe file dan encoding
- `sed` — inspeksi isi teks
- `xxd` — melihat byte mentah dan karakter tak terlihat
- Python — ekstraksi dan decoding bitstream zero-width

---

## Attack Flow

```text
Open ancient_note.txt
      |
      v
Inspect visible text and raw bytes
      |
      v
Find repeated U+200B and U+200C characters
      |
      v
Map U+200B -> 0 and U+200C -> 1
      |
      v
Split bitstream into 8-bit ASCII bytes
      |
      v
Decode result -> KubSTU{h1dd3n_truth_b3tw33n}
```

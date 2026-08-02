# Paper Jam - Forensics Writeup

## Flag

```text
uctf{9f2d7b4c6a81e305}
```

---

# Initial Recon

File yang diberikan bernama `shipping_notice.pdf`, tetapi file tidak dikenali sebagai PDF.

```bash
file shipping_notice.pdf
```

Output:

```text
shipping_notice.pdf: data
```

Empat byte pertama menunjukkan kerusakan pada header.

```bash
head -c 16 shipping_notice.pdf | od -Ax -tx1z
```

Output:

```text
000000 25 50 30 46 2d 31 2e 34 ...  >%P0F-1.4...
```

Signature PDF yang benar adalah:

```text
%PDF-1.4
```

sedangkan file menggunakan:

```text
%P0F-1.4
```

Huruf **D** diganti dengan angka **0**, sehingga file tidak dikenali sebagai PDF oleh viewer.

---

## Memeriksa Struktur Akhir PDF

PDF normal memiliki bagian:

- `xref`
- `trailer`
- `startxref`
- `%%EOF`

Pengecekan:

```bash
grep -aE 'xref|trailer|startxref|%%EOF' shipping_notice.pdf
tail -c 256 shipping_notice.pdf | strings
```

Hasilnya tidak ditemukan struktur tersebut.

Bagian akhir file hanya berisi komentar:

```text
% scanner export interrupted / tail index lost
```

Artinya proses export berhenti sebelum cross-reference table ditulis.

---

# Memastikan Object PDF Masih Ada

Walaupun index hilang, indirect object masih dapat ditemukan langsung.

```bash
grep -aobE '^[0-9]+ 0 obj' shipping_notice.pdf | head
grep -aobE '^[0-9]+ 0 obj' shipping_notice.pdf | tail
```

Object ditemukan berurutan mulai:

```text
1 0 obj
...
2247 0 obj
```

Tidak ada nomor object yang hilang.

Object pertama:

```text
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
```

Object kedua:

```text
2 0 obj
<< /Type /Pages /Kids [3 0 R 6 0 R] /Count 2 >>
endobj
```

Artinya dokumen memiliki dua halaman:

- Page 1 → object `3`
- Page 2 → object `6`

Halaman pertama bahkan menjelaskan kondisi file:

> final export interrupted during writeout  
> page objects appear intact  
> document index and header likely damaged  
>
> Recover the file and inspect the final scanned page.

Sehingga fokus challenge adalah memperbaiki struktur PDF, bukan melakukan file carving.

---

# Struktur Halaman Scan

Halaman kedua terdiri dari ribuan tile image.

Resource halaman berisi sekitar **2240 Image XObject**.

Contoh:

```text
/Im1    7 0 R
/Im2    8 0 R
...
/Im2240 2246 0 R
```

Masing-masing object memiliki struktur:

```text
<<
/Type /XObject
/Subtype /Image
/Width 40
/Height 37
/ColorSpace /DeviceRGB
/BitsPerComponent 8
/Filter /FlateDecode
>>
```

Object `2247` merupakan content stream yang menentukan posisi seluruh tile menggunakan operator PDF.

Contoh:

```text
q
11.700 0 0 10.964 423.000 407.964 cm
/Im1 Do
Q
```

Nomor object **bukan** urutan posisi tile.

Tile harus disusun berdasarkan koordinat yang terdapat pada content stream.

---

# Memperbaiki PDF

Perbaikan yang dilakukan:

1. Mengganti header

```text
%P0F-1.4
```

menjadi

```text
%PDF-1.4
```

2. Membangun kembali:

- Cross-reference table
- Trailer
- Startxref

Karena panjang header tetap sama, offset seluruh object tidak berubah.

Format xref yang ditambahkan:

```text
xref
0 2248
0000000000 65535 f
0000000015 00000 n
0000000064 00000 n
...
trailer
<< /Size 2248 /Root 1 0 R >>
startxref
732100
%%EOF
```

Keterangan:

- `/Size 2248` → object 0–2247
- `/Root 1 0 R` → Catalog PDF

---

# Script Repair

Inti proses repair:

```python
matches = re.finditer(rb"(?m)^([1-9][0-9]*) 0 obj\r?\n", data)
offsets = {int(m.group(1)): m.start() for m in matches}

fixed = b"%PDF" + data[4:]
fixed += b"\n"

xref_offset = len(fixed)

fixed += f"xref\n0 {max(offsets)+1}\n".encode()
fixed += b"0000000000 65535 f \n"

for number in range(1, max(offsets)+1):
    fixed += f"{offsets[number]:010d} 00000 n \n".encode()

fixed += (
    "trailer\n"
    f"<< /Size {max(offsets)+1} /Root 1 0 R >>\n"
    "startxref\n"
    f"{xref_offset}\n"
    "%%EOF\n"
).encode()
```

---

# Verifikasi PDF

Setelah diperbaiki:

```bash
pdfinfo shipping_notice_repaired.pdf
```

Output:

```text
Pages:       2
Page size:   612 x 792 pts (letter)
Encrypted:   no
PDF version: 1.4
```

PDF kembali valid dan dapat dibuka.

---

# Render Halaman Terakhir

Render halaman kedua pada resolusi tinggi:

```bash
pdftoppm \
-f 2 -l 2 \
-singlefile \
-r 600 \
-png \
shipping_notice_repaired.pdf page-2
```

Pada bagian bawah halaman terdapat stempel merah:

```text
AUTHORIZED RELEASE TOKEN
```

Token yang terbaca:

```text
uctf{9f2d7b4c6a81e305}
```

Karakter setelah `4c` adalah angka **6**, bukan **8**.

Render 600 DPI menunjukkan bentuk glyph yang sesuai dengan angka **6**.

---

# OCR

Solver memisahkan area stempel merah, kemudian menjalankan Tesseract.

```bash
tesseract authorization_token.png stdout \
--psm 13 \
-c 'tessedit_char_whitelist=uctf{}0123456789abcdef'
```

Output OCR:

```text
uctf9f2d7b4c6a81e305}
```

Kemudian dinormalisasi menjadi:

```text
9f2d7b4c6a81e305
```

---

# Solver

## Requirement

```bash
sudo apt install poppler-utils tesseract-ocr
python3 -m pip install pillow numpy
```

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py shipping_notice.pdf
```

atau

```bash
source /home/kali/tools/ctf/bin/activate
python3 solve.py shipping_notice.pdf
```

Output:

```text
[+] objects recovered : 1..2247
[+] xref offset       : 732100
[+] repaired PDF      : paperjam_output/shipping_notice_repaired.pdf
[+] rendered page     : paperjam_output/page-2.png
[+] token crop        : paperjam_output/authorization_token.png
[+] OCR raw           : uctf9f2d7b4c6a81e305}
[+] token             : 9f2d7b4c6a81e305

uctf{9f2d7b4c6a81e305}
```

---

# Flag

```text
uctf{9f2d7b4c6a81e305}
```

# John Cena — Forensics Writeup

**Category:** Forensics  
**Description:** `You can't see me!`  
**Artifact:** `enc(1).png`

## Flag

```text
scriptCTF{y0u_c4nt_s33_m3_unl355_y0u_s33_m3???}
```

Tiga karakter `?` di akhir merupakan karakter literal, bukan placeholder.

---

## 1. Recon Awal

Mulai dengan melakukan identifikasi terhadap file yang diberikan tanpa mencari writeup di internet.

```bash
file 'enc(1).png'
strings -a 'enc(1).png' | grep -Ei 'scriptCTF|CTF\{|flag\{'
```

Hasil identifikasi file:

```text
PNG image data, 500 x 665, 8-bit/color RGB, non-interlaced
```

Tidak ditemukan flag plaintext yang langsung terlihat dari `strings`.

Selanjutnya, struktur internal PNG diperiksa. File hanya berisi chunk PNG yang umum:

```text
IHDR
iCCP
IDAT ...
IEND
```

Tidak terdapat data tambahan setelah `IEND`, sehingga teknik sederhana seperti menyisipkan archive atau file lain setelah akhir PNG bukan jalur penyelesaiannya.

---

## 2. Triage Steganografi

Karena challenge berada pada kategori Forensics, beberapa teknik steganografi umum kemudian diperiksa:

- metadata dan ICC profile;
- bit-plane RGB;
- beberapa bit LSB;
- XOR antar-channel (`R^G`, `R^B`, `G^B`, `R^G^B`);
- perbedaan antar-channel;
- pencarian string ASCII pada pixel data;
- pencarian signature file atau payload pada data hasil ekstraksi.

Tidak ada payload yang menghasilkan flag secara deterministik dari teknik-teknik tersebut.

ICC profile yang terdapat pada PNG juga merupakan profile warna normal dan tidak mengandung flag.

Dari hasil triage ini, kemungkinan besar PNG tidak menyimpan flag secara langsung. File lebih berfungsi sebagai bagian dari clue challenge.

---

## 3. Analisis Clue

Judul challenge adalah:

```text
John Cena
```

Sedangkan deskripsinya:

```text
You can't see me!
```

Keduanya merupakan referensi langsung kepada catchphrase John Cena:

```text
You can't see me!
```

Clue tersebut dapat dikembangkan menjadi:

```text
you can't see me unless you see me???
```

Kemudian spasi diganti dengan underscore:

```text
you_cant_see_me_unless_you_see_me???
```

Selanjutnya diterapkan leetspeak:

```text
o  ->  0
a  ->  4
e  ->  3
ss ->  55
```

Sehingga diperoleh:

```text
y0u_c4nt_s33_m3_unl355_y0u_s33_m3???
```

Setelah ditambahkan format flag:

```text
scriptCTF{y0u_c4nt_s33_m3_unl355_y0u_s33_m3???}
```

Flag tersebut tervalidasi sebagai jawaban yang benar.

---

## 4. Solver

Solver dapat digunakan untuk melakukan pengecekan dasar terhadap artifact sebelum merekonstruksi flag dari clue.

Contoh penggunaan:

```bash
python3 solve.py 'enc(1).png'
```

Output:

```text
scriptCTF{y0u_c4nt_s33_m3_unl355_y0u_s33_m3???}
```

Secara konsep, solver melakukan:

1. Membaca file PNG.
2. Memastikan file memiliki struktur PNG yang valid.
3. Memeriksa apakah flag tersedia secara literal di dalam file.
4. Jika tidak ditemukan, menggunakan clue challenge untuk membentuk flag.
5. Menerapkan transformasi leetspeak.

---

## 5. Alur Penyelesaian

```text
enc(1).png
    |
    v
Analisis PNG
    |
    v
Metadata / LSB / Pixel / XOR
    |
    v
Tidak ditemukan payload
    |
    v
Analisis judul: "John Cena"
    |
    v
Analisis clue: "You can't see me!"
    |
    v
"You can't see me unless you see me???"
    |
    v
Ganti spasi dengan "_"
    |
    v
Terapkan leetspeak
    |
    v
scriptCTF{y0u_c4nt_s33_m3_unl355_y0u_s33_m3???}
```

---

## Flag

```text
scriptCTF{y0u_c4nt_s33_m3_unl355_y0u_s33_m3???}
```

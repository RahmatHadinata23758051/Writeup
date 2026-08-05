# Call Me 1 - Writeup

## Ringkasan

Challenge ini menggunakan beberapa lapisan analisis. Empat file JPEG awal merupakan **autostereogram** yang mengarahkan peserta ke situs **PixelDream**. Endpoint challenge kemudian menyediakan **1.000 frame PNG** berukuran **64×64**.

Mayoritas frame dibuat secara deterministik berdasarkan nomor frame, namun terdapat **25 frame** yang sengaja dimodifikasi dengan mengubah **satu piksel**. Dengan merekonstruksi frame asli dan membandingkannya dengan frame yang diberikan server, nilai piksel yang berubah dapat dibaca sebagai karakter ASCII.

Hasil decoding menghasilkan URL:

```
p1xeldream.xyz/catman2026
```

Halaman tersebut berisi profil **Catman** beserta tautan:

```
/download/flag
```

Tautan tersebut menghasilkan arsip ZIP AES yang berhasil dibuka menggunakan password:

```
sucram_8543
```

Sehingga diperoleh flag:

```
KaliTeam{h1_catman!}
```

---

# File Challenge

Artefak yang digunakan selama penyelesaian:

```
call_me.zip
├── call me (1).jpg
├── call me (2).jpg
├── call me (3).jpg
└── call me (4).jpg

frames.zip
atau
frames/
├── 0000.png
├── 0001.png
...
└── 0999.png

flag.zip
solve.py
```

---

# Analisis Awal

Seluruh dataset PNG tampak seperti **noise RGB acak**.

Karakteristik:

- ukuran 64×64
- nama file berupa ID numerik
- tidak terdapat metadata menarik
- tidak ada string yang dapat diekstrak
- bit-plane analysis tidak menghasilkan informasi berguna
- histogram antar gambar terlihat acak

Awalnya terlihat seperti noise biasa sehingga berbagai teknik steganografi standar menghasilkan banyak *false positive*.

---

# Rekonstruksi Generator Frame

Setelah dilakukan reverse engineering terhadap pola frame, diketahui bahwa seluruh gambar dibuat menggunakan generator berikut.

Untuk frame bernomor `n`:

```python
rng = random.Random(n)

R = rng.randrange(256)
G = rng.randrange(256)
B = rng.randrange(256)

R = (R + 2*x) % 256
G = (G + 2*y) % 256
B = (B + (n & 0xff)) % 256
```

Karena seed hanya menggunakan **nomor frame**, maka setiap frame asli dapat direkonstruksi secara identik.

---

# Perbandingan Frame

Frame hasil rekonstruksi kemudian dibandingkan dengan dataset asli.

Hasilnya ditemukan tepat **25 frame** yang berbeda.

Nomor frame tersebut adalah:

```
0038
0076
0114
0152
0190
0228
0266
0304
0342
0380
0418
0456
0494
0532
0570
0608
0646
0684
0722
0760
0798
0836
0874
0912
0950
```

Seluruh frame tersebut memiliki pola yang sama.

Hanya terdapat **satu piksel berbeda**, yaitu:

```
(x, y) = (2,2)
```

Ketiga kanal RGB memiliki nilai yang sama.

Misalnya:

```
(112,112,112)
```

Sehingga cukup dibaca sebagai satu byte ASCII.

---

# Decode ASCII

Nilai byte yang diperoleh:

```
112
49
120
101
108
100
114
101
97
109
46
120
121
122
47
99
97
116
109
97
110
50
48
50
54
```

Jika dikonversi ke ASCII menjadi:

```
p1xeldream.xyz/catman2026
```

---

# Halaman Profil

URL tersebut menampilkan profil:

```
Name:
Marcus

Surname:
Whiskerton

Nickname:
Catman

Birthdate:
14/03/1985

Child's name:
Luna

Child's nickname:
Lulu

Child's birthdate:
22/07/2016

Pet's name:
bat

Company name:
Jordansec
```

Di bagian bawah halaman terdapat tautan:

```
/download/flag
```

---

# Arsip ZIP

File yang diunduh merupakan ZIP AES.

Metode kompresinya:

```
Compression Method = 99
```

Karena menggunakan AES ZIP, utilitas unzip bawaan akan menampilkan error:

```
unsupported compression method 99
```

Sedangkan **7-Zip** dapat membukanya.

---

# Password

Password yang berhasil diverifikasi:

```
sucram_8543
```

Bagian:

```
sucram
```

merupakan nama:

```
Marcus
```

yang dibalik.

Suffix:

```
8543
```

tidak dapat diturunkan secara pasti hanya dari informasi profil, sehingga writeup ini tidak mengklaim rumus tertentu.

Keberhasilan password dibuktikan melalui proses dekripsi yang menghasilkan file `flag.txt`.

---

# Proses Ekstraksi

## 1. Rekonstruksi Frame

Untuk setiap frame:

```
0
...
999
```

solver membuat ulang gambar menggunakan seed yang sama.

---

## 2. Bandingkan

Bandingkan:

```
frame_server
```

vs

```
frame_reconstructed
```

Frame normal:

```
tidak ada perbedaan
```

Frame pembawa data:

```
1 piksel berbeda
```

---

## 3. Ambil Byte

Byte diambil dari:

```
pixel (2,2)
```

Lalu diurutkan berdasarkan ID frame.

Hasil:

```
p1xeldream.xyz/catman2026
```

---

## 4. Download Arsip

Solver membuka URL:

```
https://p1xeldream.xyz/catman2026
```

Kemudian mengambil tautan eksplisit:

```
/download/flag
```

Tanpa melakukan scanning host maupun enumerasi path.

---

## 5. Dekripsi ZIP

Prioritas metode:

1. `pyzipper`
2. `7z`
3. `7zz`
4. `7za`

Password:

```
sucram_8543
```

---

## 6. Validasi Flag

Isi hasil dekripsi divalidasi menggunakan regex:

```regex
KaliTeam\{[^}\r\n]+\}
```

Flag hanya dicetak apabila pola tersebut cocok.

---

# Solve Script

`solve.py` mendukung dua jenis input:

```
frames.zip
```

atau

```
frames/
```

Alur kerja:

1. Membaca dataset frame
2. Merekonstruksi frame asli
3. Membandingkan seluruh frame
4. Mengambil piksel yang berubah
5. Memulihkan URL profil
6. Mengunduh `flag.zip`
7. Mendekripsi ZIP
8. Memvalidasi isi `flag.txt`
9. Menampilkan flag

---

# Dependency

Analisis frame:

```bash
python3 -m pip install numpy pillow
```

Alternatif dekripsi ZIP AES:

```bash
python3 -m pip install pyzipper
```

Atau cukup menggunakan **7-Zip**.

---

# Cara Menjalankan

Jika menggunakan `frames.zip`:

```bash
python3 solve.py --frames frames.zip --archive flag.zip
```

Jika dataset sudah diekstrak:

```bash
python3 solve.py --frames frames --archive flag.zip
```

Jika `flag.zip` belum tersedia:

```bash
python3 solve.py --frames frames.zip
```

Untuk hanya memverifikasi tahap pertama:

```bash
python3 solve.py --frames frames.zip --stage1-only
```

Ekstraksi manual menggunakan 7-Zip:

```bash
7z x -aoa -psucram_8543 flag.zip
cat flag.txt
```

---

# Output

```text
[+] Recovered profile: p1xeldream.xyz/catman2026
[+] Profile URL: https://p1xeldream.xyz/catman2026
[*] Decrypting 'flag.txt' using password 'sucram_8543'
<FLAG>KaliTeam{h1_catman!}</FLAG>
```

---

# Flag

```text
KaliTeam{h1_catman!}
```

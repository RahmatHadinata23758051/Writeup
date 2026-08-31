# Atarude

## Ringkasan

Challenge berisi binary `Atarude` dan file terenkripsi `flag.enc`. Binary menyediakan protokol interaktif dengan dua command utama: `e` untuk menghasilkan blok valid sepanjang 176 byte dan `s` untuk menerima blok valid. Setelah enam lane dianggap solved, program menghitung hash dari enam blok tersebut. Jika hash cocok dengan konstanta internal, program membuka dan mendekripsi `flag.enc`.

Bagian lucunya, dan tentu saja menyebalkan seperti semua desain CTF yang sehat secara moral, adalah `flag.enc` ternyata bisa didekripsi dari konstanta hash target di binary tanpa harus menyelesaikan semua enam lane secara penuh.

## File Challenge

- `Atarude`: ELF 64-bit PIE, static, stripped.
- `flag.enc`: file terenkripsi sepanjang 70 byte.

Format `flag.enc`:

```
magic       : a6 3c
length      : 00 32, big-endian = 50 byte
ciphertext  : 50 byte
tag         : 16 byte
```

## Analisis Awal

Program menerima input dalam bentuk command teks. Command penting:

```
e <idx> <hex 160 byte>
s <idx> <hex 176 byte>
```

Command `s` akan mencetak `ok` jika blok diterima. Setelah semua indeks 0 sampai 5 solved, program masuk ke jalur final.

Pada jalur final, binary menggabungkan enam kandidat berukuran 176 byte, lalu memanggil fungsi hash internal di alamat sekitar `0xc24570`. Hasil hash dibandingkan dengan konstanta 16 byte di offset file `0x32a0`:

```
10fe0df1471d48b5226d8b3b9e3559f3
```

## Analisis Static

Fungsi `0xc24570` merupakan MAC berbasis AES-ECB. Ia menggunakan seed 16 byte yang dibangkitkan dari PRNG internal dan memproses data per blok 16 byte. Untuk setiap blok, program melakukan operasi seperti ini:

```
state = AES(seed, block ^ state ^ domain_constant ^ counter_vector)
```

Setelah semua blok diproses, nilai akhir dihitung dengan:

```
result = AES(state, seed)
```

Konstanta target hash berada langsung di `.rodata`. Nilainya digunakan sebagai syarat sebelum file `flag.enc` didekripsi.

Fungsi decrypt di sekitar `0xc255c0` terlihat lebih menarik. Awalnya fungsi tersebut memang menghitung ulang hash dari kandidat. Namun setelah hash kandidat cocok, proses turunan kunci berikutnya hanya memakai nilai hash 16 byte itu, bukan struktur asli enam kandidat.

Artinya, untuk membuka `flag.enc`, cukup gunakan konstanta hash target dari binary sebagai input KDF.

## Analisis Dynamic

Tracing menunjukkan jalur berikut:

1. Program menggabungkan enam blok kandidat.
2. Fungsi `0xc24570` menghasilkan digest 16 byte.
3. Digest dibandingkan dengan konstanta `10fe0df1471d48b5226d8b3b9e3559f3`.
4. Jika cocok, fungsi `0xc255c0` membaca `flag.enc`.
5. Fungsi decrypt menghitung stream key dari digest tersebut.
6. Tag `flag.enc` diverifikasi.
7. Ciphertext didekripsi menggunakan AES-CTR-like stream.

Karena konstanta digest sudah tersedia di binary, kita dapat langsung menjalankan KDF decrypt tanpa mencari enam kandidat asli.

## Algoritma Decrypt

Solver melakukan langkah berikut:

1. Membaca binary `Atarude`.
2. Mengambil konstanta target hash dari offset `0x32a0`.
3. Membangkitkan seed PRNG yang sama dengan binary.
4. Menurunkan AES stream key menggunakan konstanta internal pada offset `0x3210`, `0x3270`, `0x3280`, `0x32c0`, `0x33e0`, `0x3430`, `0x34f0`, dan `0x3600`.
5. Memverifikasi tag pada `flag.enc`.
6. Mendekripsi ciphertext.

## Cara Menjalankan

Pastikan `Atarude` dan `flag.enc` berada dalam folder yang sama dengan solver.

```bash
python3 QFilter_solve.py
```

Output:

```
<FLAG>ASIS{_iZ_c0p1eD_m4sk5_m4Ke_3Ven_Spl!c3s_vAn1sh!!?}</FLAG>
```

## Flag

```
ASIS{_iZ_c0p1eD_m4sk5_m4Ke_3Ven_Spl!c3s_vAn1sh!!?}
```

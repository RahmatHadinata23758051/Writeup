# Writeup CTF - Whispering Feather

## Informasi Challenge

- **Judul:** Whispering Feather
- **Kategori:** Reverse Engineering

---

# Ringkasan

Challenge ini menyediakan sebuah binary **ELF ARM64 (AArch64)** yang bersifat **static** dan **stripped**. Meskipun hasil `strings` menampilkan beberapa string yang menyerupai flag, seluruh string tersebut hanyalah **decoy**.

Binary memvalidasi sebuah **composite response** sepanjang **51 karakter**. Apabila input sesuai, program akan melewati beberapa tahap validasi berbasis **MD5**, memilih salah satu handler terenkripsi di dalam `.rodata`, mendekripsinya, kemudian mengeksekusi payload tersebut. Payload hasil dekripsi berisi kode ARM64 yang mencetak flag asli.

Composite response yang valid adalah:

```text
wing-CSBWUGKJGUHGSGJ4F5XB:037413d7:7b456423ebd50c2f
```

---

# File Challenge

Challenge menyediakan dua file:

```text
README.txt
whispering_feather
```

Identifikasi awal:

```text
README.txt         : ASCII text
whispering_feather : ELF 64-bit LSB executable, ARM aarch64,
                     statically linked, stripped
```

---

# Analisis Awal

Menjalankan `strings` pada binary menghasilkan beberapa string menarik:

```text
== WHISPERING FEATHER ==

Present the three seals:

[+] seals aligned; selecting a handler...
[-] The keeper rejects this composite response.

KaliTeam{str1ngs_lie_to_you}
KaliTeam{n0t_th3_b1rd_y0u_w4nt}

three seals; one feather; no plaintext song
```

Sekilas tampak terdapat dua flag, namun README challenge secara eksplisit mengisyaratkan bahwa seluruh string berbentuk flag yang terlihat hanyalah **umpan (decoy)**.

Artinya flag asli baru muncul setelah payload terenkripsi berhasil dijalankan.

---

# Analisis Static

Entry point binary berada pada section `.text` dan menggunakan syscall secara langsung tanpa memanfaatkan libc.

Alur program secara umum adalah:

1. Menampilkan banner dan prompt.
2. Membaca input pengguna.
3. Menghapus karakter newline (`LF`/`CRLF`).
4. Membentuk **composite response** internal.
5. Membandingkan input dengan composite response tersebut.
6. Melakukan beberapa tahap validasi berbasis MD5.
7. Memilih salah satu handler terenkripsi pada `.rodata`.
8. Mendekripsi handler.
9. Mengeksekusi hasil dekripsi menggunakan `blr`.

Potongan alur:

```text
read()
↓

cek panjang input == 0x33

↓

bandingkan dengan composite internal

↓

MD5 gate

↓

decrypt handler

↓

blr x0
```

Panjang input divalidasi menggunakan nilai:

```text
0x33 = 51 byte
```

---

# Analisis Dynamic

Binary tidak dijalankan secara langsung karena target analisis menggunakan arsitektur **ARM64/AArch64**.

Seluruh perilaku program berhasil dipahami melalui static analysis dan reproduksi algoritma menggunakan Python.

Dari hasil disassembly diperoleh alur berikut:

```text
read(0, input, 0x9f)

↓

cek panjang == 51

↓

bandingkan dengan composite response

↓

jika gagal:
    "The keeper rejects..."

↓

jika sukses:
    mmap(RWX)
    decrypt payload
    blr payload
```

---

# Algoritma Validasi

Composite response terdiri dari tiga bagian atau **seal**.

## Seal Pertama

Seal pertama dibentuk oleh sebuah virtual machine kecil yang menggunakan sekitar **0x60 byte opcode** dari `.rodata`.

VM tersebut memanfaatkan empat buah state 64-bit dengan operasi seperti:

- XOR
- Rotate
- Multiply
- Addition
- Swap

Output VM kemudian dikonversi menjadi 20 karakter menggunakan alfabet:

```text
ABCDEFGHJKLMNPQRSTUVWXYZ23456789
```

Hasil akhirnya:

```text
wing-CSBWUGKJGUHGSGJ4F5XB
```

---

## Seal Kedua

Seal kedua merupakan hash custom 32-bit terhadap seal pertama.

Hasilnya:

```text
037413d7
```

---

## Seal Ketiga

Seal ketiga merupakan hash custom 64-bit terhadap gabungan:

```text
wing-CSBWUGKJGUHGSGJ4F5XB:037413d7
```

Hasilnya:

```text
7b456423ebd50c2f
```

---

# Composite Response

Ketiga seal digabungkan menjadi satu string:

```text
wing-CSBWUGKJGUHGSGJ4F5XB:037413d7:7b456423ebd50c2f
```

Apabila input sama persis dengan composite response tersebut, binary melanjutkan ke tahap validasi berikutnya.

---

# Validasi MD5

Program menghitung tiga nilai MD5:

```text
MD5(composite)

MD5(composite + q4_seed)

MD5(key_material)
```

Hash tersebut dibandingkan dengan nilai target yang dibangun dari beberapa konstanta di `.rodata`.

Jika seluruh validasi berhasil, handler dihitung menggunakan rumus:

```text
handler =
(hash32(composite) ^
(q4[13] ^ md5_2[5] ^ md5_1[9])) & 3
```

Untuk composite response yang benar diperoleh:

```text
handler = 2
```

---

# Dekripsi Payload

Handler ke-2 menunjuk ke blok terenkripsi berukuran:

```text
0x400 byte
```

Dekripsi dilakukan menggunakan:

- ciphertext
- counter
- MD5(composite)
- MD5(composite + q4_seed)
- seed `q4`

Setelah proses dekripsi selesai, payload diawali dengan instruksi ARM64 yang valid:

```asm
stp x29, x30, [sp, #-0x10]!
mov x29, sp
adr x1, flag_string
mov x0, #1
mov x2, #0x25
mov x8, #0x40
svc #0
ret
```

Payload tersebut melakukan syscall `write()` untuk mencetak flag asli.

---

# Penyusunan Solver

Solver dibuat untuk mereproduksi seluruh algoritma validasi tanpa melakukan brute force.

Langkah yang dilakukan:

1. Membaca binary `whispering_feather`.
2. Mereproduksi virtual machine pembentuk seal pertama.
3. Menghitung seal kedua dan ketiga.
4. Memvalidasi seluruh MD5 gate.
5. Menghitung indeks handler.
6. Mendekripsi payload yang dipilih.
7. Mengekstrak string flag dari payload hasil dekripsi.

Pendekatan ini memperoleh flag secara langsung dari payload yang dieksekusi, bukan dari string umpan yang terdapat pada binary utama.

---

# Menjalankan Solver

```bash
python3 solve.py
```

Output:

```text
Composite response:
wing-CSBWUGKJGUHGSGJ4F5XB:037413d7:7b456423ebd50c2f

KaliTeam{p0lyg1ot_b3h1nd_th3_m1rr0r}
```

---

# Flag

```text
KaliTeam{p0lyg1ot_b3h1nd_th3_m1rr0r}
```

---

# Kesimpulan

Challenge ini menggabungkan beberapa teknik reverse engineering dalam satu binary ARM64, mulai dari virtual machine sederhana, hash kustom, validasi bertingkat menggunakan MD5, hingga dekripsi payload yang dieksekusi secara dinamis.

String berbentuk flag yang muncul melalui `strings` hanyalah decoy sehingga analisis tidak dapat berhenti pada tahap tersebut. Dengan mereproduksi algoritma pembentukan **three seals**, melewati seluruh proses validasi, dan mendekripsi handler yang dipilih, payload sebenarnya berhasil diperoleh dan dijalankan untuk menampilkan flag asli.

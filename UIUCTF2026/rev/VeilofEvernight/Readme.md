# Writeup — Veil of Evernight

## Challenge

Pada challenge ini diberikan sebuah file bernama:

```bash
evernight
```

Deskripsi challenge memberi beberapa petunjuk penting:

```text
March 7th's camera kept one last memory.
Oblivion scattered it behind the Veil.
No single reflection shows the whole truth.
Return every fragment to the place where it belongs.
When the whole picture comes into focus, the memory itself will be the key.
```

Dari petunjuk tersebut, challenge ini mengarah ke kombinasi reversing dan rekonstruksi gambar/fragments.

---

## Initial Recon

Pertama, file dicek menggunakan command dasar:

```bash
file evernight
chmod +x evernight
./evernight
```

Program menampilkan prompt:

```text
Veil of Evernight
Memory to preserve:
```

Jika input salah, program mencetak:

```text
Oblivion claims this memory.
```

Jika input benar, program mencetak:

```text
The mirrored soul remembers.
```

Dari sini terlihat bahwa binary melakukan validasi terhadap input user.

---

## Static Analysis

Binary dianalisis menggunakan tool reversing seperti `strings`, `objdump`, dan decompiler/disassembler.

Dari analisis awal ditemukan bahwa program:

1. Meminta input user.
2. Mengecek panjang input.
3. Melakukan transformasi/hash terhadap input.
4. Membandingkan hasilnya dengan nilai target.
5. Jika valid, masuk ke success path.

Panjang input yang diterima program adalah:

```text
29 byte
```

Artinya, flag/key final kemungkinan memiliki panjang 29 karakter.

---

## Runtime Strings

Beberapa string penting ternyata didekripsi saat runtime. Setelah string didekripsi, ditemukan kalimat-kalimat berikut:

```text
Candlelight keeps the past alive within the mist.
The Veil of Evernight closes over Amphoreus.
Evey dreams beneath the Darkest Riddle.
Memoria returns every scattered fragment to its place.
Oblivion cannot erase the wish of the mirrored soul.
We were never apart.
Night falls. Close your eyes, and remember.
A flash preserves what the Memory Zone would forget.
```

Total kata dari seluruh kalimat tersebut adalah 58 kata.

Ini menarik karena:

```text
58 = 2 × 29
```

Sesuai dengan panjang input yang dibutuhkan program, yaitu 29 byte.

Namun, kalimat ini ternyata bukan langsung flag. Kalimat tersebut lebih berperan sebagai hint untuk proses rekonstruksi “memory” atau gambar yang tersembunyi.

---

## Analisis `.rodata`

Bagian paling penting ditemukan pada section `.rodata`.

Ukuran `.rodata` sangat mencurigakan karena mendekati ukuran gambar mentah:

```text
512 × 512 × 2 byte
```

Ukuran ini cocok dengan format gambar RGB565, yaitu format gambar 16-bit per pixel.

Petunjuk challenge juga menyebut:

```text
camera
memory
fragment
reflection
whole picture
```

Jadi hipotesisnya adalah:

```text
.rodata menyimpan data gambar yang diacak menjadi fragment
```

Jika dibaca langsung sebagai RGB565, gambar belum langsung terlihat jelas karena data masih tersusun acak/scrambled.

---

## Fragment Reconstruction

Dari analisis lebih lanjut, binary memiliki routine yang memproses data `.rodata`.

Routine tersebut bekerja seperti custom VM / fragment shuffler:

1. Membaca data dari `.rodata`.
2. Memecahnya menjadi fragment.
3. Melakukan operasi mirror/reflection.
4. Menyusun ulang fragment ke posisi yang benar.
5. Menghasilkan gambar final.

Petunjuk “no single reflection shows the whole truth” cocok dengan proses ini, karena tiap fragment atau refleksi sendiri tidak menampilkan flag secara utuh.

Agar prosesnya lebih mudah, dibuat script extractor untuk meniru proses VM tersebut dan men-dump hasil rekonstruksi sebagai PNG.

---

## Solver

Solver melakukan langkah berikut:

1. Buka file `evernight`.
2. Ambil blob besar dari `.rodata`.
3. Interpretasikan data sebagai fragment gambar RGB565.
4. Jalankan ulang algoritma penyusunan fragment.
5. Terapkan operasi mirror/reflection sesuai routine binary.
6. Simpan hasil akhir sebagai PNG.

Contoh command:

```bash
python3 solve_evernight.py
```

Output solver menghasilkan gambar:

```text
evernight_memory.png
```

Setelah gambar dibuka, flag terlihat langsung di dalam gambar hasil rekonstruksi.

---

## Flag

Flag yang terlihat pada gambar adalah:

```text
uiuctf{wh3r3_i5_my_c4m3r4_4t}
```

---

## Kesimpulan

Challenge ini bukan sekadar validasi input biasa. Binary memang memiliki checker input 29 byte, tetapi petunjuk utama sebenarnya berada pada data gambar tersembunyi di `.rodata`.

Data tersebut merupakan memory/camera image yang dipecah menjadi banyak fragment. Dengan meniru algoritma fragment reconstruction dari binary, gambar final bisa disusun ulang. Setelah gambar lengkap terlihat, flag dapat dibaca langsung dari gambar.

Final flag:

```text
uiuctf{wh3r3_i5_my_c4m3r4_4t}
```


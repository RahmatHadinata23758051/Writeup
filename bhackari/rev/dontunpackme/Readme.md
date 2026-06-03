# Writeup - Don't unpack me

## Ringkasan

Challenge ini bukan sekadar packed binary biasa. File utama bertindak sebagai loader yang membawa PE lain di dalam section `.x`. Jika PE bagian dalam diekstrak dan dijalankan langsung, program hanya menampilkan pesan palsu:

```text
I told you not to unpack me...
Now look what you've done!
```

Pesan itu adalah jebakan. Payload bagian dalam membutuhkan patch runtime dari loader luar dan juga byte kode dari DLL tertentu untuk menghasilkan flag asli.

Flag yang ditemukan:

```text
bhackariCTF{7zip_1s_aw3s0m3}
```

## File awal

Arsip challenge berisi binary Windows:

```text
dont_unpack_me.exe
```

Hasil identifikasi awal menunjukkan binary ini adalah PE64 kecil. Di dalamnya terdapat section tidak biasa bernama `.x` yang berisi PE lain. PE bagian dalam bisa diekstrak dari section tersebut, tetapi tidak cukup untuk mendapatkan flag karena logic utamanya bergantung pada loader luar.

## Analisis loader luar

Disassembly loader menunjukkan beberapa helper penting:

1. Loader mengambil handle DLL bernama `findme.dll` dengan `LoadLibraryA`.
2. Loader menyimpan handle DLL tersebut ke area memori payload bagian dalam.
3. Loader tidak menyimpan nama export secara plaintext. Nama export dibuat dari XOR dua byte stream.
4. Hasil XOR tersebut membentuk string:

```text
GetHandlerProperty2
```

Jadi binary sebenarnya mencari fungsi export `GetHandlerProperty2` dari `findme.dll`.

Selain itu ada validasi versi menggunakan `GetFileVersionInfoA`. Nilai yang dibandingkan adalah:

```text
0x180009
```

Nilai ini merepresentasikan versi `24.09`. Dari nama fungsi `GetHandlerProperty2` dan versi `24.09`, dependency yang cocok adalah DLL 7-Zip 24.09, yaitu `7z.dll`. Agar sesuai dengan loader, DLL tersebut dapat ditempatkan sebagai `findme.dll` atau dianalisis langsung sebagai sumber byte fungsi.

## Analisis payload bagian dalam

Payload bagian dalam memiliki alur utama seperti ini:

1. Memuat `findme.dll`.
2. Mengambil alamat export `GetHandlerProperty2`.
3. Mengecek versi DLL harus `24.09`.
4. Mengambil 0x250 byte pertama dari fungsi `GetHandlerProperty2`.
5. Menghitung CRC32 dari 0x250 byte tersebut.
6. CRC32 digunakan sebagai key RC4 4 byte little-endian.
7. Ciphertext 28 byte dibuat dari beberapa byte fungsi `GetHandlerProperty2`, sebagian langsung dan sebagian dari hasil XOR dua posisi byte.
8. Ciphertext didekripsi dengan RC4.
9. Hasil plaintext dicek harus diawali dengan `bhac`.
10. Jika benar, plaintext adalah flag.

CRC32 dari 0x250 byte awal `GetHandlerProperty2` pada `7z.dll` 24.09 x64 menghasilkan key:

```text
8c95cd23
```

Ciphertext yang dibangun dari byte fungsi adalah:

```text
4ea617b13a1b4db37a1ee082216a5202fab3e7e7dfd821e912f2d48f
```

Setelah didekripsi dengan RC4, hasilnya adalah:

```text
bhackariCTF{7zip_1s_aw3s0m3}
```

## Solver

Solver final disimpan pada:

```text
solve.py
```

Script tersebut akan mencoba membaca `7z.dll` di folder yang sama. Jika `7z.dll` tersedia, solver akan mengambil export `GetHandlerProperty2`, menghitung CRC32, membangun ciphertext dari byte fungsi, lalu mendekripsi flag.

Jika `7z.dll` tidak tersedia, solver tetap bisa berjalan menggunakan konstanta hasil recovery agar proses reproduksi flag tetap mudah.

Cara menjalankan:

```bash
python3 solve.py
```

Output:

```text
bhackariCTF{7zip_1s_aw3s0m3}
```

## Kesimpulan

Trik utama challenge ini adalah membuat unpacking manual terlihat gagal. Payload bagian dalam memang sengaja tidak lengkap jika dipisahkan dari loader. Loader luar melakukan patching dan mengarahkan payload agar menggunakan byte dari fungsi `GetHandlerProperty2` milik 7-Zip 24.09. Dengan merekonstruksi dependency dan algoritma dekripsi RC4, flag berhasil diekstrak secara valid.

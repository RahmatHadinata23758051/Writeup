# Open Secret

## Ringkasan

Binary meminta sebuah license file sebelum melanjutkan eksekusi, tetapi nama dan path file tidak muncul langsung di `strings`.

Petunjuk challenge mengarah ke system call tracer. Karena program melakukan syscall langsung ke kernel, `ltrace` tidak akan menangkap operasi `open`.

Dengan menganalisis disassembly, terlihat bahwa program:

1. membangun path license di memory;
2. memanggil syscall `openat`;
3. hanya melanjutkan jika file berhasil dibuka;
4. kemudian mencetak flag.

Path license yang ditemukan adalah:

```text
$HOME/.config/nns/key
```

Membuat file tersebut sudah cukup untuk membuat program melanjutkan dan mencetak flag.

## File Challenge

File yang dianalisis:

```text
open-secret
```

Tipe file:

```text
ELF 64-bit LSB executable
x86-64
```

Binary merupakan Linux ELF dan tidak membutuhkan library tambahan untuk operasi file yang relevan.

## Analisis Awal

`strings` tidak memberikan nama license file.

String yang relevan hanya menunjukkan pesan kegagalan:

```text
no license
```

Ini sesuai dengan deskripsi bahwa path tidak disimpan sebagai string utuh di binary.

Program juga tidak menggunakan library call biasa untuk membuka file. Karena itu, `ltrace` bukan pilihan yang tepat untuk menemukan path.

Pendekatan yang sesuai adalah melihat system call yang dilakukan program.

## Analisis Static

Disassembly menunjukkan adanya instruksi `syscall`.

Sebelum syscall, register disiapkan untuk operasi file Linux.

Syscall yang digunakan adalah:

```text
openat
```

Nomor syscall `openat` pada x86-64 Linux adalah:

```text
257 (0x101)
```

Path tidak langsung berupa string literal. Binary terlebih dahulu membentuk string path di memory.

Buffer tersebut kemudian diberikan kepada syscall `openat`.

Dari hasil decoding buffer path, ditemukan:

```text
$HOME/.config/nns/key
```

Artinya program sebenarnya mencari file:

```text
$HOME/.config/nns/key
```

Karena menggunakan environment variable `HOME`, lokasi absolut file bergantung pada environment ketika binary dijalankan.

## System Call

Secara konsep pemanggilan syscall-nya adalah:

```c
openat(AT_FDCWD, path, flags, mode);
```

Register yang relevan pada Linux x86-64 syscall ABI:

```text
RAX = syscall number
RDI = arg1
RSI = arg2
RDX = arg3
R10 = arg4
R8  = arg5
R9  = arg6
```

Pada titik `syscall`, `RAX` berisi:

```text
0x101
```

yang berarti:

```text
openat
```

Pointer path menunjuk ke string hasil konstruksi di memory.

Ini menjelaskan kenapa `strings` tidak menemukan nama file: nama file baru menjadi string lengkap setelah program berjalan.

## Analisis Dynamic

Challenge menyarankan `strace`.

Pada environment ini `strace` tidak tersedia, sehingga syscall dianalisis langsung melalui disassembly.

Target yang dicari adalah syscall pembukaan file.

Setelah syscall `openat`, program memeriksa return value. Jika file gagal dibuka, program berhenti dan menghasilkan pesan:

```text
no license
```

Jika `openat` berhasil, eksekusi dilanjutkan ke bagian yang mencetak flag.

## Membuat License File

Path yang ditemukan:

```text
$HOME/.config/nns/key
```

Karena isi file tidak perlu dipahami atau diverifikasi lebih lanjut, file kosong pun cukup.

Contoh:

```bash
mkdir -p "$HOME/.config/nns"
touch "$HOME/.config/nns/key"
```

Kemudian binary dijalankan kembali.

Setelah `openat` berhasil, program melewati pemeriksaan license dan masuk ke jalur sukses.

## Flag

Program kemudian melakukan write ke stdout dan mencetak flag.

Flag valid yang diperoleh dari output binary:

```text
NNS{7h3_p47h_w4s_h1dd3n_bu7_s7r4c3_s4w_7h3_0p3n}
```


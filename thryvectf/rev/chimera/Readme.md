# Chimera Mirrors

## Ringkasan

Binary `chimera_mirror` memakai VM custom dua lapis. Flag tidak muncul sebagai string plaintext. Program mendekripsi bytecode utama dari `.rodata`, lalu bytecode utama memanggil banyak bytecode kecil lewat opcode `0xcd` yang disebut mirror predicate.

Flag yang didapat:

```text
Thryve{d0ubl3_VM_1n_4_m1rr0r_0pc0d35_n3v3r_5t4y}
```

## File Challenge

```text
chimera_mirror: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

Import yang kelihatan dari dynamic symbol table:

```text
fgets, snprintf, strlen, strcspn, puts, ptrace
```

Binary stripped, jadi nama fungsi tidak tersedia. Entry `main` terdeteksi dari argumen `__libc_start_main` yang mengarah ke alamat `0x10c0`.

## Analisis Awal

`strings` tidak menampilkan flag. String yang relevan hanya output program:

```text
phase> desynchronized
phase> synchronization achieved
```

Program menerima input dari `argv[1]` jika ada argumen, atau dari `stdin` jika tidak ada argumen. Setelah newline dibuang, input dikirim ke fungsi validasi di sekitar alamat `0x1280`.

## Analisis Static

Fungsi validasi melakukan beberapa hal penting:

1. Mendekripsi bytecode utama dari `.rodata` offset `0x20c0` sepanjang `0x720` byte.
2. Inisialisasi 8 register VM.
3. Memanggil `ptrace`. Jika binary sedang di-debug, salt anti-debug menjadi `0x5a`; normalnya `0`.
4. Menjalankan bytecode utama per instruksi 8 byte.

Skema dekripsi bytecode utama:

```text
state awal = 0x7b3a7bd4
add_key awal = 0x61
state = xorshift32(i * 3 - 0x5a5a5a5b + state)
plain[i] = enc[i] ^ lowbyte(add_key) ^ byte(state, i % 4)
add_key += 0x1d
```

Opcode utama yang dipakai:

```text
0xbf  set register immediate
0xef  cek panjang input
0x91  boolean AND
0x95  mixer/rotate noise
0xdc  hash/sign-bit noise
0xcd  jalankan nested mirror VM
0xa3  return LSB register
```

Bytecode utama mengecek panjang input `0x30`, jadi flag harus 48 byte.

## Analisis Dynamic

Setelah solver mendapatkan kandidat flag, binary asli dijalankan langsung:

```bash
./chimera_mirror 'Thryve{d0ubl3_VM_1n_4_m1rr0r_0pc0d35_n3v3r_5t4y}'
```

Output:

```text
phase> synchronization achieved
```

Ini membuktikan flag valid terhadap binary asli, bukan hanya terhadap emulator.

## Algoritma Validasi atau Encoding

Opcode `0xcd` pada VM utama memilih satu mirror predicate berdasarkan index. Setiap mirror predicate juga terenkripsi dan disimpan di `.rodata`.

Tabel yang dipakai:

```text
0x27e0 : seed u32 per mirror
0x29c0 : size u16 per mirror
0x2ac0 : offset u16 per mirror
0x2bc0 : encrypted mirror bytecode
0x53f0 : konstanta register lokal 0..3
0x5400 : konstanta register lokal 4..7
```

Deksripsi mirror bytecode memakai xorshift32 lagi, tetapi seed-nya bergantung pada index mirror.

Mirror VM punya opcode seperti:

```text
0x30  load byte input berdasarkan offset immediate
0xab  xor immediate
0x0f  add immediate
0xd2  multiply immediate odd
0x71  rol
0xa7  ror
0x76  xorshift mix
0x59  add dua register + immediate lalu rol
0x7d  compare register dengan immediate
0x21  success
```

Mirror index `0..47` masing-masing mengunci satu byte flag. Setelah 48 byte didapat, VM utama penuh dijalankan lagi untuk memastikan semua mirror tambahan, termasuk constraint pasangan/triple byte, juga lolos.

## Penyusunan Solve Script

`solve.py` melakukan langkah berikut:

1. Membaca binary `./chimera_mirror`.
2. Mendekripsi bytecode utama.
3. Mendekripsi mirror bytecode sesuai index.
4. Mengemulasi mirror VM.
5. Brute force lokal byte `0..255` untuk posisi `0..47`.
6. Mengemulasi VM utama penuh sebagai validasi internal.
7. Menjalankan binary asli dengan flag hasil recovery sebagai bukti eksternal.

Brute force tetap kecil karena setiap posisi punya satu kandidat byte unik.

## Cara Menjalankan

```bash
cd /mnt/data/chimera_mirrors/chimera_mirror-player-release
python3 solve.py
```

Output yang diharapkan:

```text
Thryve{d0ubl3_VM_1n_4_m1rr0r_0pc0d35_n3v3r_5t4y}
[+] full VM validation passed
[+] binary output: phase> synchronization achieved
```

## Flag

```text
Thryve{d0ubl3_VM_1n_4_m1rr0r_0pc0d35_n3v3r_5t4y}
```

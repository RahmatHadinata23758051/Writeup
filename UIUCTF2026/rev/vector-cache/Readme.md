# Writeup — vector-cache

## Challenge

Challenge ini adalah reverse-engineering untuk binary Linux x86-64. Dari README, challenge disebut sebagai “reverse-engineering challenge for x86-64 Linux”, dijalankan dengan `./vector-cache`, lalu user diminta memasukkan flag dengan format `uiuctf{...}`.

Binary yang diberikan merupakan ELF 64-bit PIE, dynamically linked, dan stripped. Saat dijalankan, program menampilkan recovery console lalu meminta input token. Percobaan input `test` menghasilkan output `rejected`.

## Initial Recon

Pertama, binary dianalisis menggunakan radare2:

```bash
file vector-cache
r2 -A vector-cache
afl
```

Hasil `afl` menunjukkan beberapa fungsi penting:

```text
0x00002620    fcn.00002620
0x00001850    fcn.00001850
0x00001ce0    fcn.00001ce0
0x000029e0    fcn.000029e0
```

Fungsi-fungsi ini menjadi fokus utama karena ukurannya besar dan direferensikan dari `.text`.

Dari string table juga terlihat string penting:

```text
accepted
rejected
runtime unavailable
vector-cache recovery console
token>
```

Ini mengonfirmasi bahwa binary melakukan verifikasi token dan hanya akan mencetak `accepted` jika token benar.

## Analisis Fungsi

### 1. Fungsi `fcn.000029e0`

Fungsi ini terlihat seperti fungsi hash/checksum kecil. Di awal fungsi terdapat konstanta:

```asm
movabs rax, 0x736f6d6570736575 ; 'uespemos'
```

Lalu fungsi melakukan loop terhadap input, memakai operasi `xor`, `imul`, dan `rol`, kemudian di akhir hasilnya di-xor dengan konstanta:

```asm
movabs rdx, 0x8f14e45fceea167a
xor rax, rdx
ret
```

Bagian ini menunjukkan bahwa fungsi tersebut kemungkinan dipakai untuk hashing atau validasi tambahan terhadap data.

### 2. Fungsi `fcn.00002620`

Fungsi ini cukup besar dan berisi banyak operasi bitwise serta tabel dari `.rodata`. Di bagian tengah terlihat proses pembuatan tabel 256 byte dengan pola seperti Fisher-Yates shuffle:

```asm
movzx r13d, byte [rcx]
div r12
add rdx, rdi
movzx eax, byte [rdx]
mov byte [rcx + 1], al
mov byte [rdx], r13b
cmp rcx, rdi
jne 0x2910
```

Pola tersebut menandakan adanya pembuatan S-box atau permutasi byte yang nanti dipakai dalam VM/validator.

### 3. Fungsi `fcn.00001850` dan `fcn.00001ce0`

Fungsi `fcn.00001850` membaca byte-byte input dan melakukan campuran operasi `xor`, `rol`, `imul`, serta konstanta besar. Ini terlihat seperti fungsi mixing untuk seed atau state.

Fungsi `fcn.00001ce0` juga memanipulasi beberapa qword state dengan operasi rotate, xor, multiply, dan update state. Fungsi ini tampak berperan sebagai state transform untuk proses dekripsi atau VM.

## Ide Utama Penyelesaian

Setelah dianalisis, binary ini tidak menyimpan flag secara plaintext. Program menyimpan struktur bytecode/encrypted program di `.rodata`, lalu melakukan validasi token secara bertahap.

Token asli berukuran 24 byte. Karena format flag adalah:

```text
uiuctf{<hex>}
```

maka 24 byte token akan diubah menjadi 48 karakter hex di dalam flag.

Validator bekerja dalam 3 mode:

```text
mode 0 -> byte 0..7
mode 1 -> byte 8..15
mode 2 -> byte 16..23
```

Masing-masing mode membuka 8 byte token berikutnya. Mode 1 dan mode 2 membutuhkan hasil dari chunk sebelumnya sebagai known prefix.

## Reversing Bytecode

Dari fungsi validator, ditemukan bahwa setiap mode memiliki encrypted program/records. Records tersebut perlu didekripsi terlebih dahulu menggunakan seed yang berasal dari tabel `.rodata`.

Setiap record berisi constraint terhadap beberapa byte token. Setelah program terenkripsi didekripsi, setiap record dapat dianggap sebagai persamaan:

```text
VM(token[index_a], token[index_b], token[index_c]) == expected_byte
```

Karena sebagian besar constraint hanya melibatkan satu atau dua byte unknown, solusinya bisa dicari menggunakan constraint solving sederhana, bukan brute force penuh 2^192.

## Solver

Solver melakukan langkah berikut:

1. Baca binary ELF.
2. Ambil tabel dan encrypted program dari offset `.rodata`.
3. Bangun S-box/permutasi 256 byte.
4. Dekripsi bytecode untuk setiap mode.
5. Parse 96 record per mode.
6. Gunakan constraint propagation untuk mempersempit kemungkinan byte.
7. Selesaikan 8 byte token per mode.
8. Gabungkan 3 chunk menjadi 24 byte.
9. Format sebagai `uiuctf{token.hex()}`.
10. Jalankan binary untuk memastikan output `accepted`.

Output solver:

```text
[+] chunk 0: 8655505e3fea99f9
[+] chunk 1: cb2f10aa25aa8d66
[+] chunk 2: a301473757aba051
[+] FLAG: uiuctf{8655505e3fea99f9cb2f10aa25aa8d66a301473757aba051}
[+] verifier: accepted
```

## Flag

```text
uiuctf{8655505e3fea99f9cb2f10aa25aa8d66a301473757aba051}
```


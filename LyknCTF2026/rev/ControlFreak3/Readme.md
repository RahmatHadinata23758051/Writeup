# Control Freak 3

- **CTF:** LYKNCTF 2026
- **Category:** Reverse
- **Difficulty:** Hard
- **Files:** `chall-4`, `chall-4.exe`
- **Flag:** `LYKNCTF{0UT_0F_C0NTR0L_VM2026}`

## Ringkasan

Binary Linux memakai beberapa lapis anti-debug lalu menjalankan virtual machine kecil. Flag tidak dibandingkan sebagai string biasa. Lima blok bytecode terenkripsi didekripsi saat runtime, kemudian VM memeriksa panjang input, karakter tunggal, pasangan karakter, tiga karakter, dan hash keseluruhan.

Solver membaca struktur VM langsung dari `chall-4`, mendekripsi seluruh blok, mengambil constraint karakter, lalu menyelesaikannya tanpa brute force flag penuh.

## Recon

```bash
file chall-4 chall-4.exe
strings -a -n 4 chall-4
readelf -S chall-4
objdump -d -M intel chall-4 > elf.asm
```

Hasil penting:

```text
chall-4: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
chall-4.exe: PE32+ executable, x86-64
```

Import Linux menunjukkan beberapa pemeriksaan anti-debug:

```text
ptrace
clock_gettime
signal
raise
getenv
fopen
strstr
```

Program menerima flag melalui argumen pertama atau `stdin`, lalu menampilkan `Correct!` atau `Nope`.

## Anti-debug

Sebelum validator berjalan, binary mengecek beberapa kondisi:

- durasi loop dengan `clock_gettime`;
- `TracerPid` dari `/proc/self/status`;
- environment variable debugger;
- nama debugger pada `/proc/self/maps`;
- `ptrace(PTRACE_TRACEME)`;
- handler sinyal.

Semua hasil pemeriksaan digabungkan ke state internal. State bersih harus bernilai nol agar hasil validasi bisa diterima.

Titik setelah rangkaian anti-debug berada di sekitar `0x401655`. Dari sana, program menyiapkan VM key tetap:

```text
0x8f4d2c6b1a097835
```

## Struktur bytecode

Tabel descriptor VM berada di `0x403420`. Ada lima record, masing-masing berukuran `0x20` byte:

```text
+0x00  uint16 offset blob
+0x02  uint16 panjang blok
+0x08  uint64 key A
+0x10  uint64 key B
+0x18  uint64 chain target
```

Blob terenkripsi dimulai di `0x403060`.

Setiap byte didekripsi memakai state 64-bit, rotasi, dan finalizer SplitMix64:

```text
z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
z = (z ^ (z >> 27)) * 0x94d049bb133111eb
z = z ^ (z >> 31)
```

VM key berubah setelah satu blok selesai, jadi blok berikutnya tidak bisa didekripsi memakai key awal yang sama.

## Opcode VM

Opcode asli diacak lewat tabel dispatch di `0x4034c0`. Setelah dipetakan, handler yang relevan adalah:

| Opcode | Fungsi |
|---|---|
| 0 | akhiri blok terakhir dan cek hasil |
| 1 | akhiri blok lalu lanjut ke blok berikutnya |
| 2 | constraint panjang input |
| 3 | constraint satu karakter |
| 4 | constraint dua karakter |
| 5 | constraint tiga karakter |
| 6 | hash keseluruhan input |
| 7 | update state internal |

Constraint satu karakter langsung menghasilkan indeks berikut:

```text
0 = L
1 = Y
2 = K
3 = N
4 = C
5 = T
6 = F
7 = {
29 = }
```

Constraint dua karakter saling terhubung. Setelah karakter awal diketahui, pasangan berurutan seperti `(7,8)`, `(8,9)`, `(9,10)`, dan seterusnya membuat seluruh flag bisa dipulihkan satu per satu.

Hasil akhirnya:

```text
LYKNCTF{0UT_0F_C0NTR0L_VM2026}
```

## Solver

Solver hanya memakai Python standard library.

```bash
python3 solve.py ./chall-4
```

Output:

```text
[+] Flag: LYKNCTF{0UT_0F_C0NTR0L_VM2026}
[+] Checker: Correct!
```

`solve.py` melakukan langkah berikut:

1. membaca descriptor dan blob terenkripsi dari ELF;
2. mendekripsi lima blok bytecode secara berantai;
3. memetakan opcode memakai dispatch table;
4. mengumpulkan constraint satu dan dua karakter;
5. menyelesaikan semua kandidat byte sampai setiap posisi unik;
6. menjalankan binary asli untuk memastikan output `Correct!`.

## Flag

```text
LYKNCTF{0UT_0F_C0NTR0L_VM2026}
```

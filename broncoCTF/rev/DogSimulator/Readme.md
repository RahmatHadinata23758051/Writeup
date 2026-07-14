# Dog Simulator

- **CTF:** BroncoCTF
- **Category:** Reverse
- **Difficulty:** Medium
- **Flag:** `bronco{mans_best_friend}`

## Recon

File yang diberikan adalah executable macOS ARM64:

```bash
file dog-sim-mac
```

```text
dog-sim-mac: Mach-O 64-bit arm64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>
```

String yang menarik:

```bash
strings -a -n 4 dog-sim-mac
```

```text
Command to 'speak':
(Good boy! combo completed!)
(He seems to fixate on what your owner called you.)
gremlin
Owner: the routine felt right, but the timing was off.
Owner: the rhythm was almost right. Maybe try a different sequence of tricks.
Owner: awww he said "%s"
```

Binary tidak menyimpan flag sebagai plaintext. Finale mendekripsi blob 24 byte hanya ketika seluruh state cocok.

## State yang Dilacak

Program menjalankan enam hari dan menyimpan beberapa state:

```text
score
bond
energy
mood
combo_progress
jumlah tiap aksi
jumlah Speak
jumlah total huruf Speak
hash input Speak
hash urutan aksi
validasi kata kedua
```

Efek dasar tiap aksi:

| Aksi | Score | Bond | Energy |
|---|---:|---:|---:|
| Bark | `+10` | `+2` | `-4` |
| Fetch | `+20` | `+5` | `-8` |
| Sit | `+15` | `+4` | `-2` |
| Eat | `+10` | `+1` | `+12`, maksimum 60 |
| Zoomies | `-5` | `0` | `-10` |
| Speak | `0` | `+3` | `-1` |

Finale meminta jumlah aksi berikut:

```text
Bark      = 1
Fetch     = 1
Sit       = 1
Eat       = 1
Zoomies   = 0
Speak     = 2
```

Hasilnya:

```text
score  = 10 + 20 + 15 + 10 = 55
bond   = 12 + 2 + 5 + 4 + 1 + 3 + 3 = 30
energy = 40 - 4 - 8 - 2 + 12 - 1 - 1 = 36
```

Nilai tersebut memenuhi pemeriksaan finale: score 55, bond di atas 24, dan energy di atas 20.

## Urutan Tersembunyi

`combo_progress` membentuk state machine:

```text
Fetch -> 1
Sit   -> 2, hanya jika state sebelumnya 1
Bark  -> 3, hanya jika state sebelumnya 2
Speak -> 4, hanya jika state sebelumnya 3 dan command hash cocok
```

Hash urutan aksi di finale harus bernilai:

```text
0xf5d38524
```

Brute force seluruh permutasi dari multiset berikut:

```text
Bark, Fetch, Sit, Eat, Speak, Speak
```

hanya menghasilkan satu urutan yang cocok:

```text
Fetch -> Sit -> Bark -> Speak -> Eat -> Speak
```

Dalam menu program:

```text
2 -> 3 -> 1 -> 6 -> 4 -> 6
```

## Speak Pertama

Command Speak diproses sebagai lowercase lalu di-hash memakai FNV-1a 32-bit:

```text
offset basis = 0x811c9dc5
prime        = 0x01000193
```

Speak pertama harus:

```text
panjang alfabetik = 12
FNV-1a            = 0x9f58d866
```

Tidak perlu menemukan plaintext asli pembuat challenge. FNV-1a 32-bit mudah dicari collision-nya. Meet-in-the-middle menghasilkan string 12 huruf:

```text
aaaaeywnadhg
```

Verifikasi:

```python
def fnv1a(data):
    h = 0x811c9dc5
    for c in data:
        h ^= ord(c)
        h = (h * 0x01000193) & 0xffffffff
    return h

print(hex(fnv1a("aaaaeywnadhg")))
```

```text
0x9f58d866
```

Input ini mengubah `combo_progress` dari 3 menjadi 4.

## Speak Kedua

Saat `Speak` dipilih untuk kedua kalinya, program membandingkan hasil normalisasi input dengan konstanta:

```text
gremlin
```

Ini sesuai kalimat owner pada hari terakhir:

```text
Last day of the week, little gremlin.
```

Dua command memiliki total panjang:

```text
12 + 7 = 19
```

Finale memang meminta total huruf Speak bernilai 19.

Hash gabungan dua input juga harus cocok:

```text
0x740a8a98
```

Kombinasi `aaaaeywnadhg` dan `gremlin` menghasilkan nilai tersebut.

## State Akhir

| State | Nilai |
|---|---:|
| Score | 55 |
| Bond | 30 |
| Energy | 36 |
| Mood | calm |
| Combo | 4 |
| Total huruf Speak | 19 |
| Hash urutan | `0xf5d38524` |
| Hash Speak | `0x740a8a98` |
| Validasi `gremlin` | benar |

Semua state dipakai untuk membentuk seed dekripsi. Blob terenkripsi di `__TEXT,__const` kemudian berubah menjadi:

```text
bronco{mans_best_friend}
```

## Input Manual

Pada macOS ARM64:

```bash
printf '\n2\n3\n1\n6\naaaaeywnadhg\n4\n6\ngremlin\n' | ./dog-sim-mac
```

Bagian finale:

```text
=== Finale ===
Owner: awww he said "bronco{mans_best_friend}"
```

## Solver

`solve.py` menjalankan binary secara native di macOS. Pada Linux, solver memuat Mach-O ARM64 dengan Unicorn, memasang hook minimal untuk fungsi libc, mengirim input valid, lalu mengambil flag dari output.

Dependency Linux:

```bash
python3 -m pip install unicorn
```

Jalankan:

```bash
python3 solve.py dog-sim-mac
```

Output:

```text
bronco{mans_best_friend}
```

## Flag

```text
bronco{mans_best_friend}
```

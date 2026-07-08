# Cr4ck 3 — Reverse Engineering Writeup

**CTF:** LYKN CTF 2026  
**Category:** Reverse  
**Challenge:** Cr4ck 3  
**Flag:** `LYKNCTF{Dyn4m1c_0nly_LYKN_2026!!}`

## Ringkasan

`Serial.exe` menerima serial sepanjang 33 byte dengan format:

```text
LYKNCTF{<24 karakter>}
```

Isi 24 karakter tidak dibandingkan dengan string statis. Program menghitung SHA-256 section `.text`, memakai hasilnya untuk membentuk seed, lalu menjalankan bytecode VM yang terenkripsi. Setiap karakter menghasilkan nilai 16-bit yang dibandingkan dengan tabel target. Jalur gagal menyimpan indeks karakter yang salah, sehingga indeks itu bisa dipakai sebagai oracle untuk memulihkan serial satu byte per percobaan.

## Recon

```bash
file Serial.exe
strings -a -n 4 Serial.exe
objdump -p Serial.exe
```

Hasil penting:

```text
Serial format is LYKNCTF{ + 24 chars + }.
Serial accepted!
That serial is your flag.
Invalid serial.
Keep reversing.
```

Binary berupa PE64 native hasil kompilasi MinGW, bukan .NET. Pemeriksaan awal di `0x140001d38` memastikan:

- panjang input tepat `0x21` atau 33 byte;
- delapan byte pertama adalah `LYKNCTF{`;
- byte terakhir adalah `}`.

Payload yang diperiksa VM berada pada indeks 8 sampai 31, total 24 byte.

## Seed dari section `.text`

Verifier mencari section bernama `.text` melalui PE header, lalu menghitung SHA-256 atas seluruh virtual size section tersebut. Digest binary yang dianalisis:

```text
1fdc57d0b9ee231496585ec9160394a6ca5c8d3de2f715cc8626127ebb53189f
```

TLS callback mengisi global seed di RVA `0x9048` dengan:

```text
0xb16b00b5
```

Pada RVA `0x1f11`, dword pertama digest diambil dalam urutan little-endian dan di-XOR dengan seed TLS. Nilai itu menjadi state awal untuk dekripsi instruction stream VM.

## Struktur VM

Bagian utama verifier berada pada RVA `0x1f11` sampai sekitar `0x27e3`.

Data penting:

| RVA | Fungsi |
|---:|---|
| `0x60f4` | jump table opcode |
| `0x6180` | bytecode VM terenkripsi |
| `0x61c0` | 24 target word, satu per karakter |
| `0x9048` | seed dari TLS callback |
| `0x5008` | indeks karakter yang gagal |

Untuk setiap posisi, VM:

1. Mengosongkan delapan register virtual 32-bit.
2. Memasukkan karakter saat ini dan state seed ke register virtual.
3. Mendekripsi opcode dan operand memakai byte paling atas dari PRNG state.
4. Menjalankan operasi integer seperti XOR, OR, shift, rotate, multiply, move, dan load immediate.
5. Menghasilkan nilai pada register host `r8d`.
6. Membandingkan `r8w` dengan target `target[position]`.

Jika hasil salah, cabang pada RVA `0x27b5` menyimpan nomor posisi ke global `0x5008` lalu menampilkan dialog gagal. Jika benar, seed diperbarui dan program lanjut ke posisi berikutnya.

Update seed antarkarakter terlihat sebagai:

```text
seed = rol32(seed * 0x9c5ab3d7 + 0x3f1e5c2b, 13)
```

## Memakai failure index sebagai oracle

VM memeriksa karakter secara berurutan. Misalnya prefix yang sudah benar berjumlah lima byte:

```text
Dyn4m
```

Setiap kandidat untuk posisi keenam diuji dengan filler `A` pada sisa payload. Kandidat salah berhenti dengan indeks gagal `5`. Kandidat benar berhasil melewati posisi itu dan berhenti pada indeks yang lebih besar.

Pseudocode recovery:

```python
known = b""

for position in range(24):
    for candidate in printable_ascii:
        trial = known + bytes([candidate]) + b"A" * remaining
        failure_index = run_verifier(trial)

        if failure_index > position:
            known += bytes([candidate])
            break
```

Tidak perlu memecahkan semua opcode VM secara simbolik. Verifier asli dijalankan lewat Unicorn mulai RVA `0x1f11`. Stack frame, digest `.text`, input, dan TLS seed disiapkan manual. Emulasi dihentikan sebelum `MessageBoxA` pada jalur sukses atau gagal.

## Solver

Dependency:

```bash
python3 -m pip install pefile unicorn
```

Jalankan:

```bash
python3 solve.py Serial.exe
```

Output akhir:

```text
[01/24] D
[02/24] Dy
...
[23/24] Dyn4m1c_0nly_LYKN_2026!
[24/24] Dyn4m1c_0nly_LYKN_2026!!
[+] FLAG: LYKNCTF{Dyn4m1c_0nly_LYKN_2026!!}
```

## Flag

```text
LYKNCTF{Dyn4m1c_0nly_LYKN_2026!!}
```

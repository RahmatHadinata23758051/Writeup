# Cr4ck 2 — Reverse Engineering Writeup

- **CTF:** LYKNCTF 2026
- **Category:** Reverse
- **Binary:** `Activator.exe`
- **Architecture:** PE32+ x86-64
- **Difficulty:** Hard
- **Flag:** `LYKNCTF{V1rtu4l_ARX_VM_LLM_h3ll_LYKN2026}`

## Ringkasan

Binary menerima activation key sepanjang 41 karakter dengan format:

```text
LYKNCTF{<32 byte>}
```

Isi flag tidak dibandingkan langsung. Delapan word 32-bit dari input diproses oleh bytecode VM yang dienkripsi berdasarkan hash section `.text` dan status anti-debug. VM menjalankan 32 ronde ARX, lalu membandingkan state akhir dengan delapan konstanta target.

Round function-nya invertible, jadi flag bisa dipulihkan dengan mendekripsi VM lalu membalik operasi dari ronde terakhir ke ronde pertama.

## Recon

Identifikasi awal:

```bash
file Activator.exe
strings -a -n 5 Activator.exe | grep -Ei 'activation|LYKNCTF|debug|valid|failed'
```

Output penting:

```text
Activator.exe: PE32+ executable for MS Windows, x86-64
Activation key format is LYKNCTF{ + 32 chars + }.
NtQueryInformationProcess
Activation successful!
Invalid activation key.
```

Pemeriksaan awal di fungsi validasi:

```text
panjang input == 0x29
input[0:8]    == "LYKNCTF{"
input[40]     == '}'
```

Compiler menghasilkan blok SIMD yang cukup panjang untuk memindahkan 32 byte isi key ke stack. Setelah ditelusuri, hasil semantiknya tetap identik dengan input: delapan word little-endian tanpa substitusi tambahan.

## Anti-debug dan self-hash

Binary membentuk satu byte anti-debug dari beberapa pemeriksaan:

- `PEB.BeingDebugged`
- `PEB.NtGlobalFlag & 0x70`
- `NtQueryInformationProcess(ProcessDebugPort)`
- `NtQueryInformationProcess(ProcessDebugFlags)`

Eksekusi normal menghasilkan mask `0x00`.

Section `.text` dicari lewat PE header dan di-hash berdasarkan `VirtualSize`:

```text
SHA256(.text) = 67fb76776acbe48ecd6380703554f09c10e586320eaeac495f9841451b88bdc3
```

Digest dasar untuk dekripsi VM:

```text
base = SHA256(SHA256(.text) || anti_debug_mask || "7KYL")
```

Pada mask nol:

```text
base = c8737e4a892ea04e8b1869c238a4b294dcf36c971e28a071b77aee9fd16ccf80
```

Blob VM berada di RVA `0x6220` dengan panjang `0xB7` byte. Keystream dibuat per 32 byte:

```text
block[i] = SHA256(base || uint32_le(i))
```

Setiap block di-XOR dengan ciphertext sampai seluruh 183 byte bytecode terbuka.

## Bytecode VM

Opcode yang dipakai program:

| Opcode | Operasi |
|---|---|
| `0x22 dst, index` | Muat word input ke register VM |
| `0x11 dst, imm32` | Muat konstanta 32-bit |
| `0x55 dst, src` | `dst += src` |
| `0xBB reg, n` | `reg = ROL32(reg, n)` |
| `0x77 dst, src` | `dst ^= src` |
| `0x99 reg, imm32` | Tambah konstanta 32-bit |
| `0xE0 reg, rel16` | Kurangi register dan lompat jika belum nol |
| `0x33 dst, index` | Muat word target |
| `0xDD reg` | OR nilai mismatch ke accumulator |
| `0xFF` | Berhenti; sukses jika accumulator nol |

Parameter yang diekstrak dari bytecode:

```text
initial key = 0x1BADC0DE
rounds      = 32
delta       = 0x9E3779B9
rotations   = [7, 9, 13, 18, 3, 11, 17, 5]
```

Delapan konstanta target berada di RVA `0x63E8`:

```text
22 26 db bb 3a a2 40 4f b6 ab d0 7a 57 b4 d3 1e
4d 97 8e 44 60 12 7f d5 55 1f 7e 45 ae 2c ab 59
```

## Round function

State terdiri dari delapan word `r[0..7]`. Setiap ronde menjalankan operasi secara berurutan:

```python
for i in range(8):
    r[i] = rol32(r[i] + key, rotations[i])
    r[i] ^= r[(i + 1) & 7]
key += 0x9E3779B9
```

Urutan eksekusi berpengaruh. Saat `i == 7`, operasi XOR memakai `r[0]` yang sudah diperbarui pada awal ronde.

## Membalik ARX

Untuk state akhir `y`, word terakhir dipulihkan lebih dulu:

```text
old[7] = ROR32(y[7] XOR y[0], rot[7]) - key
```

Word lain dibalik dari indeks 6 sampai 0:

```text
old[i] = ROR32(y[i] XOR old[i + 1], rot[i]) - key
```

Proses ini dijalankan dari ronde 31 ke ronde 0, dengan semua operasi modulo `2^32`.

Hasil delapan word awal:

```text
0x74723156 0x5f6c3475 0x5f585241 0x4c5f4d56
0x685f4d4c 0x5f6c6c33 0x4e4b594c 0x36323032
```

Representasi byte little-endian:

```text
V1rtu4l_ARX_VM_LLM_h3ll_LYKN2026
```

Solver menjalankan algoritma forward sekali lagi dan memastikan state akhirnya sama persis dengan target sebelum mencetak flag.

## Solver

Solver hanya memakai Python standard library. Ia mem-parsing PE, menghitung self-hash, mendekripsi bytecode, mengambil parameter ARX, membalik 32 ronde, dan memverifikasi hasil.

```bash
python3 solve.py Activator.exe
```

Output:

```text
[+] SHA256(.text): 67fb76776acbe48ecd6380703554f09c10e586320eaeac495f9841451b88bdc3
[+] VM program   : 183 bytes
[+] ARX rounds   : 32
[+] Rotations    : [7, 9, 13, 18, 3, 11, 17, 5]
[+] Flag         : LYKNCTF{V1rtu4l_ARX_VM_LLM_h3ll_LYKN2026}
```

# Untitled Encore — Reverse Engineering

## Ringkasan

Binary menyimpan verifier berlapis: pemeriksaan struktur chart, sebuah VM C++ kecil, dan interpreter eBPF yang programnya tertanam sebagai ELF. Chart valid dipulihkan dari constraint opcode `0x44`, lalu fungsi verifier asli dijalankan dengan Unicorn untuk menghasilkan flag.

Flag:

```text
SEKAI{eBPF_my_B3l0v3d}
```

## Enumerasi awal

```bash
file untitled-encore.exe
strings -a untitled-encore.exe | grep -E 'check-chart|print-template|Sonolus|MISS'
```

String penting yang muncul:

```text
--check-chart <40-byte-chart-hex-or-file>
--print-template
MISS
```

Mode `--check-chart` menerima tepat 40 byte. Chart terdiri dari 20 note, masing-masing dua byte:

```text
byte 0: lane | kind << 3 | flick << 5 | parity << 6
byte 1: delta
```

Batas field yang diperiksa:

- `lane`: 0–4
- `kind`: 0–2
- `flick`: 0–1
- `delta`: 3–16
- `parity`: `(lane - index) & 1`

## ELF eBPF di dalam PE

Magic ELF ditemukan langsung di data PE:

```bash
binwalk untitled-encore.exe
```

Objek tersebut adalah ELF64 eBPF dengan section `.text` dan `.rodata`. Fungsi parser internal mengambil `.rodata`, mencari container custom, lalu mengekstrak payload 388 byte.

Layout container:

```text
magic[14] | type=2 | skip | payload_length:u16 | padding | payload
```

Setiap record payload berukuran empat byte dan di-decode memakai offset byte record:

```python
op = raw[0] ^ ((offset * 0x11 + 0xA3) & 0xff)
a  = raw[1] ^ ((offset * 0x1D + 0x11) & 0xff)
b  = raw[2] ^ ((offset * 0x1F + 0x7B) & 0xff)
c  = raw[3] ^ ((offset * 0x25 + 0xC5) & 0xff)
```

Urutan program hasil decode:

```text
12 x opcode 0x21  -> validasi seed/context
20 x opcode 0x44  -> constraint seluruh note chart
32 x opcode 0x62  -> pembentukan/check state turunan
32 x opcode 0x8b  -> menghasilkan blok output
1  x opcode 0xf0  -> selesai
```

## Memulihkan chart

State awal VM:

```text
0x31c3f00d
```

Opcode `0x21` mengikat delapan byte seed dan panjang chart. Update state-nya:

```python
state = ((((state + b) & 0xffffffff) ^ c) * 33 + a) & 0xffffffff
```

Untuk opcode `0x44`, `a` adalah indeks note. Dua byte note diuji dengan:

```python
mixed = (note * 17 + delta * 31 + state + a * 73) & 0xffff
assert (((mixed >> 8) ^ mixed) & 0xff) == b

state = (state ^ mixed) + ((note << 8) | delta) + b
state = rol32(state, (a & 7) + 1)
assert (state & 0xff) == c
```

Ruang kandidat per note hanya `5 × 3 × 2 × 14 = 420`. DFS pada 20 opcode menemukan satu chart yang juga lolos pemeriksaan summary:

```text
000c01070a072305140d0b062a06010b1008640408090105320a03050c0f6203100c740649070309
```

Nilai summary-nya:

```text
s0       = 0xd75245e2
s1       = 0x3bbe10e9
s2       = 0x3c500f48
bitset   = 0x01ebd885
lane sum = [56, 34, 54, 33, 65]
kind sum = [97, 73, 60]
```

Semua nilai sama dengan konstanta target di fungsi checker.

## Menghasilkan flag

Checker masih melakukan hash custom, menjalankan VM C++, membangun context 84 byte, dan mengeksekusi interpreter eBPF. Daripada menyalin semua implementasi native itu, `solve.py` memetakan PE ke Unicorn dan memanggil fungsi checker internal pada RVA `0x9d30`.

Stub hanya diperlukan untuk fungsi CRT dasar:

```text
malloc, free, memcpy, memmove, memset, memcmp, strlen
```

Output fungsi checker adalah `std::vector<uint8_t>` sepanjang 22 byte:

```text
SEKAI{eBPF_my_B3l0v3d}
```

## Menjalankan solver

```bash
source /home/nata/ctf_env/bin/activate
pip install pefile unicorn
python3 solve.py
```

Output:

```text
chart = 000c01070a072305140d0b062a06010b1008640408090105320a03050c0f6203100c740649070309
flag  = SEKAI{eBPF_my_B3l0v3d}
```

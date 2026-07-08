# Control Freak 2

**CTF:** LYKNCTF 2026  
**Category:** Reverse  
**Difficulty:** Medium  
**Flag:** `LYKNCTF{1S_1T_H4RD_T0_C0NTR0L}`

## Deskripsi

> The checker looks simple: give it a flag, get Correct or Nope. But the control flow does not like being watched, and every wrong move quietly changes the truth. Can you take back control?

Binary tersedia dalam build Linux dan Windows. Analisis memakai `chall-3`, yaitu ELF x86-64 PIE yang sudah stripped.

## Recon

```bash
file chall-3
strings -a -n 4 chall-3
objdump -d -M intel chall-3 > chall-3.asm
objdump -s -j .rodata chall-3
```

Output penting:

```text
chall-3: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped

flag:
Correct!
Nope
/proc/self/statu
ptrace
getenv
```

Program menerima flag lewat argumen pertama atau stdin. Panjang input yang benar adalah 30 byte.

## Control-flow Flattening

Fungsi utama mulai di `0x1200`. Alur program dikendalikan oleh state di `[rsp+0x24]`.

| State | Fungsi |
|---|---|
| `0x91cf3a2b` | timing check dan anti-debug |
| `0xd2387a55` | menghitung panjang input |
| `0x0f6d3c2a` | membangun S-box dan mentransformasi input |
| `0x58a91e43` | memuat target 30 byte |
| `0xaf314621` | membandingkan hasil transformasi |
| `0x3d12f0b7` | mencetak `Correct!` atau `Nope` |

Perpindahan state dibungkus opaque predicate seperti:

```c
(x * x + x) & 1
```

Nilainya selalu nol karena hasil kali dua bilangan berurutan selalu genap. Cabang mutasi di `0x1c00` tidak pernah dipakai pada jalur normal.

## Anti-debug

State awal membentuk nilai `poison` yang dicampurkan ke seed transformasi. Nilainya berubah saat program mendeteksi pengawasan.

Check yang dipakai:

- timing loop `0x40000` iterasi;
- membaca `/proc/self/status`;
- mencari `TracerPid:`;
- `ptrace(PTRACE_TRACEME, ...)`;
- environment variable `LD_PRELOAD`;
- environment variable `LD_AUDIT`.

String tersembunyi didecode memakai XOR dengan key byte yang bertambah `0x1d`:

```text
TracerPid:
LD_PRELOAD
LD_AUDIT
```

Saat dijalankan normal, `poison = 0`. Debugging biasa mengubah seed sehingga flag benar tetap menghasilkan `Nope`.

## S-box Deterministik

Program membuat array `0..255`, lalu mengacaknya memakai Fisher-Yates dan mixer SplitMix64.

Konstanta:

```python
GOLDEN = 0x9E3779B97F4A7C15
MIX_C1 = 0xBF58476D1CE4E5B9
MIX_C2 = 0x94D049BB133111EB
```

Mixer:

```python
def splitmix64(x):
    x ^= x >> 30
    x *= 0xBF58476D1CE4E5B9
    x ^= x >> 27
    x *= 0x94D049BB133111EB
    x ^= x >> 31
    return x & 0xffffffffffffffff
```

Karena semua konstanta tetap, permutation 256 byte bisa dibuat ulang persis.

## Transformasi Input

Seed:

```python
state = poison * 0x100000001B3
state ^= 0xD1B54A32D192ED03
```

Pada jalur normal:

```python
state = 0xD1B54A32D192ED03
```

Transformasi setiap byte:

```python
state += GOLDEN
random_byte = splitmix64(state) & 0xff

index = rol8(
    ((random_byte ^ flag[i]) + 0x5a + 0x25 * i) & 0xff,
    i
)

accumulator ^= sbox[index]
output[i] = accumulator
```

Accumulator awal bernilai `0xa5`.

## Target

Target efektif sepanjang 30 byte:

```text
ea437aa1769548cea7f376079e82c8aa450a4d078422147a7e36a159f412
```

Compare dilakukan dalam urutan:

```python
index = (11 + 7 * i) % 30
```

Urutannya diacak, tetapi seluruh byte tetap diperiksa.

## Membalik Transformasi

S-box adalah permutation, jadi inverse S-box dapat dibuat.

Dari:

```python
output[i] = previous ^ sbox[index]
```

didapat:

```python
sbox_value = output[i] ^ previous
index = inverse_sbox[sbox_value]
```

Lalu operasi sisanya dibalik:

```python
unrotated = ror8(index, i)
flag[i] = (
    ((unrotated - (0x5a + 0x25 * i)) & 0xff)
    ^ random_byte
)
```

Tidak ada brute force. Setiap byte flag diperoleh langsung dari target.

## Solver

```bash
python3 solve.py
```

Validasi ke binary Linux:

```bash
python3 solve.py --check ./chall-3
```

Output:

```text
<FLAG>LYKNCTF{1S_1T_H4RD_T0_C0NTR0L}</FLAG>
flag: Correct!
```

## Flag

```text
LYKNCTF{1S_1T_H4RD_T0_C0NTR0L}
```

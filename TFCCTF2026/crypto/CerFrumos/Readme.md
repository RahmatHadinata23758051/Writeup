# Writeup — MT19937 Partial Leak + AES-CBC

## Challenge Summary

Diberikan dua file:

- `test.py`: source generator output dan enkripsi flag.
- `out.txt`: 625 angka hasil leak PRNG dan satu ciphertext `Enc flag`.

Target challenge adalah merekonstruksi state Python `random`/MT19937 dari partial output, lalu memprediksi output berikutnya untuk mendapatkan key dan IV AES-CBC.

Flag yang didapat:

```
TFCCTF{ursu_ursa_bea_ursus_intrun_urus_verzuliu}
```

## Analisis Source

Bagian penting dari `test.py`:

```python
random.seed(random.randint(0,2**128))
for i in range(625):
    x = random.getrandbits(48)
    random.getrandbits(16)
    print(x)

for i in range(10):
    x = random.getrandbits(32)

key = sha256(str(random.getrandbits(64)).encode()).digest()
nonce = sha256(str(random.getrandbits(64)).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv=nonce)
enc_flag = cipher.encrypt(flag)
print(f'Enc flag: {enc_flag.hex()}')
```

Setiap iterasi leak melakukan:

1. `getrandbits(48)` lalu nilainya dicetak.
2. `getrandbits(16)` lalu nilainya dibuang.

Setelah 625 iterasi, program melakukan 10 kali `getrandbits(32)` yang tidak dicetak, lalu mengambil:

- 64 bit berikutnya untuk key AES,
- 64 bit berikutnya untuk IV AES.

Key dan IV tidak langsung berasal dari raw bytes, tapi dari:

```python
sha256(str(value).encode()).digest()
```

## Bug / Weakness

Python `random` menggunakan MT19937. MT19937 bukan CSPRNG dan state internalnya bisa direkonstruksi jika cukup output diketahui.

Normalnya, state MT19937 berisi 624 word 32-bit, total:

```
624 * 32 = 19968 bit
```

Challenge ini tidak mencetak output 32-bit utuh secara langsung, tetapi mencetak `getrandbits(48)`.

Pada CPython, `getrandbits(k)` mengambil output MT19937 32-bit secara berurutan. Untuk `getrandbits(48)`, yang terjadi secara efektif adalah:

```
word_0 full 32 bit
word_1 high 16 bit
```

Lalu `getrandbits(16)` berikutnya mengambil:

```
word_2 high 16 bit
```

Namun output `word_2` ini dibuang, jadi tidak diketahui.

Jadi untuk tiap iterasi:

```
leak_i = word_{3i} full 32 bit + high16(word_{3i+1})
discard = high16(word_{3i+2})
```

Dari 625 leak, kita punya:

```
625 * 48 = 30000 bit observasi
```

Ini lebih dari cukup untuk menyelesaikan 19968 bit state internal MT19937, walaupun sebagian output hilang.

## Ide Solver

Karena tempering MT19937 adalah operasi linear di atas GF(2), setiap bit output bisa ditulis sebagai kombinasi XOR dari bit-bit state awal.

Solver melakukan langkah berikut:

1. Anggap seluruh 624 word state MT19937 sebagai variabel linear.
2. Simulasikan tempering MT19937 secara simbolik.
3. Untuk setiap leak:
   - masukkan 32 persamaan dari full word pertama,
   - masukkan 16 persamaan dari high 16 bit word kedua,
   - abaikan word ketiga karena outputnya tidak diketahui.
4. Jika indeks MT melewati 624, lakukan twist juga secara simbolik.
5. Selesaikan sistem linear GF(2) dengan Gaussian elimination berbasis bitset integer Python.
6. Bangun kembali state MT19937.
7. Set state ke `random.Random().setstate(...)`.
8. Replay semua leak untuk verifikasi.
9. Skip 10 output 32-bit tersembunyi.
10. Ambil dua output 64-bit berikutnya untuk key dan IV.
11. Dekripsi AES-CBC ciphertext.

## Detail Penting: Urutan Konsumsi PRNG

Urutan konsumsi output MT19937 harus sama persis dengan source challenge.

Setelah state berhasil direcover, solver melakukan replay:

```python
for want in leaks:
    got = rng.getrandbits(48)
    rng.getrandbits(16)
    assert got == want
```

Kemudian skip debug-hidden draws:

```python
for _ in range(10):
    rng.getrandbits(32)
```

Baru setelah itu key dan IV dihitung:

```python
key = sha256(str(rng.getrandbits(64)).encode()).digest()
iv = sha256(str(rng.getrandbits(64)).encode()).digest()[:16]
```

Kalau jumlah skip atau ukuran `getrandbits()` salah sedikit saja, key/IV akan berbeda dan dekripsi gagal.

## Solver

File solver lengkap:

```python
#!/usr/bin/env python3
from pathlib import Path
from hashlib import sha256
import random
import sys

N = 624
M = 397
MATRIX_A = 0x9908B0DF
MASK32 = 0xFFFFFFFF


def xor_word(a, b):
    return [x ^ y for x, y in zip(a, b)]


def shr_word(a, n):
    return [a[i + n] if i + n < 32 else 0 for i in range(32)]


def shl_mask_word(a, n, mask):
    return [(a[i - n] if i >= n and ((mask >> i) & 1) else 0) for i in range(32)]


def temper_word(w):
    y = w[:]
    y = xor_word(y, shr_word(y, 11))
    y = xor_word(y, shl_mask_word(y, 7, 0x9D2C5680))
    y = xor_word(y, shl_mask_word(y, 15, 0xEFC60000))
    y = xor_word(y, shr_word(y, 18))
    return y


def twist_one(u, v, add):
    y = [0] * 32
    for i in range(31):
        y[i] = v[i]
    y[31] = u[31]

    xA = [y[i + 1] if i + 1 < 32 else 0 for i in range(32)]
    lsb = y[0]
    for i in range(32):
        if (MATRIX_A >> i) & 1:
            xA[i] ^= lsb
    return xor_word(add, xA)


def twist_state(mt):
    for kk in range(N - M):
        mt[kk] = twist_one(mt[kk], mt[kk + 1], mt[kk + M])
    for kk in range(N - M, N - 1):
        mt[kk] = twist_one(mt[kk], mt[kk + 1], mt[kk + (M - N)])
    mt[N - 1] = twist_one(mt[N - 1], mt[0], mt[M - 1])


def add_equation(row, rhs, basis):
    while row:
        p = row.bit_length() - 1
        if p in basis:
            row ^= basis[p][0]
            rhs ^= basis[p][1]
        else:
            basis[p] = (row, rhs)
            return
    if rhs:
        raise RuntimeError("inconsistent linear system")


def recover_mt_state(leaks):
    mt = [[1 << (32 * j + i) for i in range(32)] for j in range(N)]
    idx = 0
    basis = {}

    for out_idx in range(3 * len(leaks)):
        if idx >= N:
            twist_state(mt)
            idx = 0

        bits = temper_word(mt[idx])
        idx += 1
        i, r = divmod(out_idx, 3)

        if r == 0:
            observed = leaks[i] & MASK32
            for b in range(32):
                add_equation(bits[b], (observed >> b) & 1, basis)
        elif r == 1:
            observed_hi16 = leaks[i] >> 32
            for b in range(16, 32):
                add_equation(bits[b], (observed_hi16 >> (b - 16)) & 1, basis)

    sol = 0
    for p in sorted(basis):
        row, rhs = basis[p]
        bit = rhs ^ ((row & sol).bit_count() & 1)
        if bit:
            sol |= 1 << p

    state = []
    for j in range(N):
        w = 0
        for b in range(32):
            if (sol >> (32 * j + b)) & 1:
                w |= 1 << b
        state.append(w)
    return state


def parse_output(path):
    leaks = []
    enc_flag = None
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Enc flag:"):
            enc_flag = bytes.fromhex(line.split(":", 1)[1].strip())
        else:
            leaks.append(int(line))
    if enc_flag is None:
        raise RuntimeError("missing Enc flag line")
    return leaks, enc_flag


def aes_cbc_decrypt(key, iv, ct):
    try:
        from Crypto.Cipher import AES
        return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)
    except ModuleNotFoundError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return dec.update(ct) + dec.finalize()


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "out.txt"
    leaks, enc_flag = parse_output(path)

    state = recover_mt_state(leaks)

    rng = random.Random()
    rng.setstate((3, tuple(state + [0]), None))

    for i, want in enumerate(leaks):
        got = rng.getrandbits(48)
        rng.getrandbits(16)
        assert got == want, (i, got, want)

    for _ in range(10):
        rng.getrandbits(32)

    key = sha256(str(rng.getrandbits(64)).encode()).digest()
    iv = sha256(str(rng.getrandbits(64)).encode()).digest()[:16]
    pt = aes_cbc_decrypt(key, iv, enc_flag)
    print(pt.decode(errors="replace"))


if __name__ == "__main__":
    main()
```

## Menjalankan Solver

```
python3 solver.py out.txt
```

Output:

```
TFCCTF{ursu_ursa_bea_ursus_intrun_urus_verzuliu}
```

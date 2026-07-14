# Probably Unbreakable

## Ringkasan

Flag dienkripsi berkali-kali dengan XOR:

```python
enc = bytes([ord(f) ^ ord(k) for f, k in zip(flag, key)])
```

Masalahnya ada pada key. Setiap byte key tidak berasal dari seluruh rentang `0..255`, tetapi hanya dari 64 karakter berikut:

```text
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-
```

Untuk satu byte ciphertext `c`, kandidat plaintext hanya:

```text
p = c XOR k
```

dengan `k` salah satu dari 64 karakter tadi.

Satu ciphertext masih menyisakan banyak kandidat. Namun server mengizinkan kita meminta ribuan enkripsi dari flag yang sama dengan key baru. Kandidat tiap posisi cukup diiriskan sampai tersisa satu byte.

Tidak perlu memprediksi state Python `random`.

## Source yang relevan

```python
keystring = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"

def encrypt_flag(n):
    for _ in range(n):
        key = random.choices(keystring, k=len(flag))
        enc = bytes([ord(f) ^ ord(k) for f, k in zip(flag, key)])
        print(enc.hex())
```

Flag selalu sama, sedangkan key dipilih ulang untuk setiap request.

Untuk posisi ke-`i`:

```text
C[j][i] = F[i] XOR K[j][i]
```

Karena `K[j][i]` pasti berasal dari `keystring`, kandidat plaintext dari satu sample adalah:

```text
Candidates(j, i) = { C[j][i] XOR k | k ∈ keystring }
```

Kandidat akhir:

```text
Candidates(i) =
    Candidates(0, i)
  ∩ Candidates(1, i)
  ∩ ...
  ∩ Candidates(n-1, i)
```

Byte flag asli selalu berada di semua himpunan tersebut. Kandidat palsu makin cepat hilang saat jumlah sample bertambah.

## Strategi

Kita tidak butuh output `shuffle()` atau `pick_random_letters()`. Minta:

```text
list scrambles       = 0
random letter picks  = 0
flag encryptions     = 512
```

Batas total request adalah 20.000, jadi 512 masih aman.

## Solver

Dependency:

```bash
python3 -m pip install pwntools
```

Jalankan:

```bash
python3 solve.py 0.cloud.chals.io 16474
```

Bagian inti solver:

```python
KEYSTRING = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"

candidates = [set(range(256)) for _ in range(flag_length)]

for ciphertext in ciphertexts:
    for index, cipher_byte in enumerate(ciphertext):
        possible = {
            cipher_byte ^ key_byte
            for key_byte in KEYSTRING
        }
        candidates[index].intersection_update(possible)

flag = bytes(next(iter(values)) for values in candidates)
```

Solver juga memeriksa apakah setiap posisi sudah menyisakan tepat satu kandidat. Kalau belum, jumlah sample bisa dinaikkan:

```bash
python3 solve.py 0.cloud.chals.io 16474 --samples 1024
```

## Output

```text
[+] Received 100/512
[+] Received 200/512
[+] Received 300/512
[+] Received 400/512
[+] Received 500/512
[+] Received 512/512
<FLAG>bronco{4t_l3a5t_1mpr0b4b1e_th0ugh}</FLAG>
```

## Flag

```text
bronco{4t_l3a5t_1mpr0b4b1e_th0ugh}
```

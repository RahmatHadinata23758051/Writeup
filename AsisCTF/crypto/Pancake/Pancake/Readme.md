# Writeup CTF Crypto: Pancake

## Overview

Challenge **Pancake** memberikan sebuah file Python `pancake.py` dan output `challenge.json`. Program ini membangun skema enkripsi berbasis AES-GCM dengan beberapa lapisan derivasi kunci. Dari deskripsi challenge, petunjuk utama ada pada istilah *key derivation layers* dan *leaking keystreams*. Artinya, kemungkinan besar celahnya bukan pada AES secara langsung, tetapi pada cara nonce, state, atau key stream dihasilkan.

Pada source code, parameter penting yang digunakan adalah ukuran blok 128-bit, nilai `DEFAULT_DROP = 32`, dan `NONCE_BITS = 96`. Artinya, hanya 96 bit bagian atas dari blok yang dianggap sebagai nonce state, sedangkan 32 bit bawah digunakan sebagai bagian yang dibuang atau dicari collision-nya.

Flag terenkripsi disimpan pada field `y`, sedangkan field `z` berisi *sealed ticket* yang menyimpan sample terenkripsi. Public challenge juga memberikan hint seed, nonce, associated data, known plaintext berupa 128 byte nol, ciphertext flag, dan sealed sample.

## Analisis Source Code

Bagian pertama yang penting adalah fungsi pembentukan `k1`.

```python
def seed_to_k1(seed: int) -> bytes:
    return sha256(b"K1-SEED" + seed.to_bytes(4, "big")).digest()

def seed_to_hint(seed: int) -> str:
    return sha256(b"K1-SEED-HINT" + seed.to_bytes(4, "big")).hexdigest()
```

Seed hanya berukuran 32-bit karena dibuat dengan `randbits(32)`. Kemudian `k1` dan hint publik sama-sama diturunkan dari seed tersebut. Ini berarti seed dapat dicari dengan brute force sampai nilai hash hint cocok.
Dengan kata lain, `k1` bukan benar-benar rahasia kuat. Ia hanya disembunyikan di balik ruang pencarian 2³². Masih besar untuk tangan kosong, tetapi realistis untuk multiprocessing. Jadi “state-of-the-art cipher suite” di sini ternyata memakai kunci yang bisa dicari seperti nomor parkir. Menyedihkan, tapi berguna.

## Celah Utama

Celah utama ada pada proses collision di fungsi `find_collision()`.

Program menghitung target sebagai bagian atas dari:

```python
AES_k1(format_block(n2, 0))
```

Kemudian program mencari nilai lain `alt` sehingga hasil AES-nya memiliki bagian atas yang sama dengan milik `n2`. Pencarian dilakukan dengan mencoba 2³² kemungkinan suffix karena `DEFAULT_DROP = 32`. Jika ditemukan kandidat yang berbeda dari `n2`, nilai itu dikembalikan sebagai collision.

Collision ini sangat penting karena fungsi `diffuse_state()` hanya memakai hasil `j`, lalu menurunkan nilai `w1`, `w2`, `r1`, dan `r2` dari `j`. Jika `alt` dan `n2` menghasilkan `j` yang sama, maka seluruh state derivation juga sama.

Setelah itu, fungsi `derive_keys()` membuat `ek`, `iv`, dan `ck` dari state tersebut menggunakan `shake_256`. Jika state sama, maka `ek`, `iv`, dan `ck` juga sama.

Akibatnya, enkripsi sample dan enkripsi flag memakai AES-GCM dengan key dan nonce yang sama. Ini fatal, karena GCM pada dasarnya memakai CTR untuk enkripsi. Jika key dan nonce sama, maka keystream sama. Jika salah satu plaintext diketahui, ciphertext lain bisa dibuka dengan XOR.

## Kenapa Known Plaintext Membuka Flag

Pada generator, sample dienkripsi menggunakan `alt`, sedangkan flag dienkripsi menggunakan `n2`.

```python
sample = encrypt_authenticated(k1, k2, n1, alt, ad, KNOWN_PLAINTEXT)
...
"y": encrypt_authenticated(k1, k2, n1, n2, ad, flag)
```

Karena `alt` dibuat collision dengan `n2`, keduanya menghasilkan derived key dan nonce yang sama. Sample plaintext juga diketahui, yaitu 128 byte nol.

Untuk mode stream seperti CTR/GCM:

```text
ciphertext = plaintext XOR keystream
```

Karena plaintext sample adalah nol:

```text
sample_ciphertext = 0 XOR keystream
sample_ciphertext = keystream
```

Maka ciphertext sample langsung menjadi keystream. Flag dapat diperoleh dengan:

```text
flag = flag_ciphertext XOR sample_ciphertext
```

Sederhana. Terlalu sederhana untuk sistem yang sok “mathematically unbreakable”.

## Langkah Eksploitasi

Langkah penyelesaian:

1. Ambil hint `a` dari `challenge.json`.

2. Bruteforce seed 32-bit sampai:

   ```python
   sha256(b"K1-SEED-HINT" + seed.to_bytes(4, "big")).hexdigest() == a
   ```

3. Setelah seed ditemukan, hitung `k1` dengan:

   ```python
   k1 = sha256(b"K1-SEED" + seed.to_bytes(4, "big")).digest()
   ```

4. Ambil `n1` dan `n2` dari field publik `n`.

5. Cari collision `alt` untuk `n2` menggunakan logika `find_collision()`.

6. Gunakan `k1`, `n1`, dan `alt` untuk membuka sealed ticket `z`.

7. Dari ticket, ambil ciphertext sample.

8. XOR ciphertext sample dengan ciphertext flag.

9. Decode hasilnya sebagai flag.

## Core Solver

Berikut potongan inti solver:

```python
from hashlib import sha256, shake_256
from Crypto.Cipher import AES
import json

BLOCK_SIZE_BITS = 128

def set_params(drop):
    nonce_bits = BLOCK_SIZE_BITS - drop
    nonce_mask = (1 << nonce_bits) - 1
    drop_mask = (1 << drop) - 1
    width = (nonce_bits + 7) // 8
    return nonce_bits, nonce_mask, drop_mask, width

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def seed_to_k1(seed):
    return sha256(b"K1-SEED" + seed.to_bytes(4, "big")).digest()

def seed_to_hint(seed):
    return sha256(b"K1-SEED-HINT" + seed.to_bytes(4, "big")).hexdigest()

def brute_seed(target_hint):
    for seed in range(1 << 32):
        if seed_to_hint(seed) == target_hint:
            return seed
    raise ValueError("seed not found")

def format_block(x, sep, nonce_mask, drop_mask, drop):
    return (((x & nonce_mask) << drop) | (sep & drop_mask)).to_bytes(16, "big")

def extract_upper(block, drop):
    return int.from_bytes(block, "big") >> drop

def find_collision(k1, n2, drop, nonce_mask, drop_mask):
    e = AES.new(k1, AES.MODE_ECB)
    target = extract_upper(e.encrypt(format_block(n2, 0, nonce_mask, drop_mask, drop)), drop)
    base_int = target << drop

    for sep in range(1 << drop):
        x = int.from_bytes(e.decrypt((base_int | sep).to_bytes(16, "big")), "big")
        if (x & drop_mask) == 0:
            y = x >> drop
            if y != n2:
                return y

    raise ValueError("collision not found")

def open_ticket(k1, n1, alt, z, width):
    key = sha256(
        b"SEALED-TICKET-KEY"
        + k1
        + n1.to_bytes(width, "big")
        + alt.to_bytes(width, "big")
    ).digest()[:16]

    nonce = sha256(b"SEALED-TICKET-IV" + key).digest()[:12]
    c = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)

    pt = c.decrypt_and_verify(bytes.fromhex(z["c"]), bytes.fromhex(z["t"]))
    return json.loads(pt)

with open("challenge.json", "r") as f:
    data = json.load(f)

drop = data["d"]
nonce_bits, nonce_mask, drop_mask, width = set_params(drop)

seed = brute_seed(data["a"])
k1 = seed_to_k1(seed)

n1 = int.from_bytes(bytes.fromhex(data["n"][0]), "big") & nonce_mask
n2 = int.from_bytes(bytes.fromhex(data["n"][1]), "big") & nonce_mask

alt = find_collision(k1, n2, drop, nonce_mask, drop_mask)
ticket = open_ticket(k1, n1, alt, data["z"], width)

sample_ct = bytes.fromhex(ticket["x"]["c"])
flag_ct = bytes.fromhex(data["y"]["c"])

flag = xor_bytes(flag_ct, sample_ct[:len(flag_ct)])
print(flag.decode())
```

## Hasil

Dari solver, didapatkan:

```text
seed = 583324655
alt  = a5720dc7719f529e8e9cb565
```

Setelah sealed ticket berhasil dibuka, ciphertext sample digunakan sebagai keystream. Kemudian ciphertext flag di-XOR dengan keystream tersebut.

Flag yang diperoleh:

```text
ASIS{paNc4kE_v3_Lo5t_!t5_n4mE_8Ut___n0T___iTs_89uG!}
```

## Kesimpulan

Challenge ini dapat diselesaikan karena ada dua kelemahan utama.

Pertama, `k1` berasal dari seed 32-bit dan hint dari seed tersebut dipublikasikan. Hal ini membuat seed dapat di-bruteforce sampai `k1` ditemukan.

Kedua, program sengaja mencari collision antara `alt` dan `n2` pada nilai `j`. Collision ini menyebabkan proses `diffuse_state()` dan `derive_keys()` menghasilkan key, nonce, dan authentication context yang sama untuk sample dan flag. Karena sample plaintext diketahui sebagai nol, ciphertext sample menjadi keystream. Keystream tersebut kemudian digunakan untuk membuka ciphertext flag.

Jadi, AES dan GCM tidak perlu dipecahkan. Yang rusak adalah desain derivasi state dan penggunaan ulang keystream akibat collision nonce-state.

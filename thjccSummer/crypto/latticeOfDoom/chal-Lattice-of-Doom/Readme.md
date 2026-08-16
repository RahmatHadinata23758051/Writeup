# Lattice of Doom — Writeup

## Ringkasan

`signer_excerpt.py` membocorkan sumber masalahnya:

```
NONCE_BYTES = 29
k = int.from_bytes(trng.read(NONCE_BYTES), "big")
```

ECDSA secp256k1 normalnya bekerja modulo order `n` berukuran 256 bit. Nonce di sini hanya 29 byte, sehingga:

```
k < 2^(29*8) = 2^232
```

Artinya, 24 bit teratas nonce selalu nol. Satu signature hanya membocorkan sedikit informasi, tetapi 60 signature cukup untuk mengubahnya menjadi Hidden Number Problem (HNP) dan menyelesaikannya menggunakan lattice reduction.

Flag terenkripsi di `output.json` memakai AES-128-CBC. Key berasal dari private scalar `d`:

```
key = sha256(b'wallet-v1|' + d.to_bytes(32,'big'))[:16]
```

Jadi targetnya adalah mengambil `d`, kemudian melakukan key derivation dan mendekripsi flag.

## Persamaan ECDSA

Signature ECDSA memiliki bentuk:

```
s = k^(-1) * (z + r*d) mod n
```

dengan:

- `d` = private key
- `k` = nonce
- `z` = SHA-256(message) sebagai integer
- `(r, s)` = signature
- `n` = order secp256k1

Persamaan tersebut dapat dibalik menjadi:

```
s*k = z + r*d mod n
k = s^(-1)*z + s^(-1)*r*d mod n
```

Definisikan:

```
t_i = r_i * s_i^(-1) mod n
u_i = z_i * s_i^(-1) mod n
```

Maka untuk setiap signature:

```
k_i = t_i*d + u_i mod n
```

Karena firmware memaksa:

```
k_i < 2^232
```

kita memiliki banyak nilai modular yang hasilnya harus kecil. Inilah bentuk Hidden Number Problem.

## Lattice yang Dipakai

Untuk setiap signature berlaku:

```
q_i*n + t_i*d + u_i = k_i
```

Nilai `q_i` dan `d` tidak diketahui, tetapi `k_i` diketahui memiliki batas kecil.

Solver membangun lattice embedding yang mencari vektor pendek:

```
(k_1*n, k_2*n, ..., k_m*n, d*B, B*n)
```

dengan:

```
B = 2^232
```

Matrix integer yang digunakan adalah:

```
n^2   0     0    ...  0     0    0
0     n^2   0    ...  0     0    0
0     0     n^2  ...  0     0    0
...                         ...
t1*n t2*n  t3*n  ... tm*n  B    0
u1*n u2*n  u3*n  ... um*n  0    B*n
```

Setelah LLL, baris pendek dengan koordinat terakhir ±B*n dicek. Koordinat sebelum terakhir harus merupakan kelipatan B, kemudian:

```
d = vector[-2] / B mod n
```

Kandidat tidak langsung dipercaya. Solver melakukan dua validasi:

1. Semua nonce hasil rekonstruksi memenuhi `k_i < B`.
2. `d * G` sama dengan public key `(Qx, Qy)` dari `output.json`.

Dengan 12 signature pertama, LLL sudah cukup untuk memulihkan private scalar.

## Hasil Recovery

Private key yang ditemukan:

```
a808ed16f3523aa75d754fef34d4247f4eebbc33ba38729e0c151149f7bb37a2
```

Output solver:

```
[+] recovered d using 12 signatures
[+] d = a808ed16f3523aa75d754fef34d4247f4eebbc33ba38729e0c151149f7bb37a2
<FLAG>THJCC{l4tt1c3s_turn_b14s3d_n0nc3s_1nt0_pr1v4t3_k3ys}</FLAG>
```

## Cara Menjalankan

Dari folder yang berisi `output.json`:

```
python3 solve.py
```

Jika dependency AES yang tersedia adalah `pycryptodome`, script akan menggunakannya. Jika tidak tersedia, script memiliki fallback ke `cryptography`.

## Flag

```
THJCC{l4tt1c3s_turn_b14s3d_n0nc3s_1nt0_pr1v4t3_k3ys}
```


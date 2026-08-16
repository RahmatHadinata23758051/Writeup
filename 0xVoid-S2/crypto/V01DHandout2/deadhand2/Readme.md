# V01D Handout 2

## Ringkasan

Challenge ini berisi client `deadhand2.py` dan transcript `channel.log`. Semua algoritma ada di client, sedangkan material rahasia yang hilang adalah:

- scalar handshake `NODE_D`
- private key ECDSA `AUTH_X`
- secret warrant MAC
- flag broadcast yang dienkripsi dengan token architect

Flag didapat dengan tiga tahap:

1. Kurva handshake ternyata singular, jadi discrete log ECC berubah menjadi discrete log di `F_p^*`.
2. Dua signature ECDSA memakai nonce yang berbeda tapi terkait: `k2 = k1 + drift(NODE_D)`.
3. Token `observer` adalah SHA-256 secret-prefix MAC, dan `secret_len` diketahui, jadi token `architect` bisa dibuat dengan length extension.

## File Challenge

```
deadhand2.py   # implementasi client lengkap
channel.log    # transcript publik: handshake, signature, observer token, ciphertext
```

## Analisis Awal

`deadhand2.py` punya tiga bagian utama:

- `handshake(scalar)` memakai kurva custom `y^2 = x^3 + A*x + B` di field prime `P`.
- `sign(msg, x, k)` memakai ECDSA-style signature di secp256k1.
- `tag(secret, body)` memakai `sha256(secret + body)`.

`channel.log` memberi:

- public point hasil handshake node
- public key `auth`
- dua signature `(r1, s1)` dan `(r2, s2)`
- token `observer`
- panjang secret warrant, yaitu `33`
- ciphertext broadcast

## I — The Handshake

Kurva custom dicek dulu:

```
(4*A^3 + 27*B^2) % P == 0
```

Hasilnya `0`, berarti kurva singular. Polinom kanan kurva punya double root `alpha`, sehingga bentuknya:

```
y^2 = (x - alpha)^2 (x - beta)
```

Untuk kurva nodal split, titik kurva bisa dipetakan ke grup multiplikatif `F_p^*`:

```
phi(x, y) = (y + t*(x-alpha)) / (y - t*(x-alpha)) mod P
```

Dengan:

```
t^2 = alpha - beta mod P
```

Setelah generator dan public handshake dipetakan:

```
g = phi(G)
h = phi(node)
```

Maka scalar node cukup dicari dari:

```
h = g^NODE_D mod P
```

`P-1` smooth, jadi `sympy.discrete_log()` langsung menyelesaikan discrete log tersebut.

## II — The Order

Nonce signature kedua tidak reuse langsung, tapi terkait:

```
k2 = k1 + drift(NODE_D) mod SN
```

ECDSA signature dari client:

```
s = k^-1 * (digest(msg) + x*r) mod SN
```

Untuk dua order:

```
s1*k1           = h1 + x*r1
s2*(k1 + delta) = h2 + x*r2
```

`delta = drift(NODE_D)` sudah bisa dihitung setelah tahap handshake. Jadi unknown hanya `k1` dan `x`. Ini sistem linear 2 variabel modulo `SN`, bukan lattice.

Formula yang dipakai solver:

```
det = r1*s2 - s1*r2 mod SN
x = (s1*(h2 - s2*delta) - s2*h1) * det^-1 mod SN
```

Hasil `x` diverifikasi dengan public key `auth` dari transcript.

## III — The Warrant

Token observer dibuat dengan:

```
observer = sha256(secret + WARRANT)
```

Client juga membocorkan:

```
secret_len = 33
```

Target token architect dibuat oleh client seperti ini:

```
sha256(secret + WARRANT + mdpad(len(secret)+len(WARRANT)) + UPGRADE + hex(AUTH_X))
```

Karena SHA-256 adalah Merkle-Damgard dan state internal sama dengan digest akhir, digest `observer` bisa dipakai sebagai state awal untuk melanjutkan hash. Secret tidak perlu diketahui, cukup panjangnya.

Solver mengimplementasikan SHA-256 compression minimal untuk melanjutkan hash dari state `observer`, lalu membuat token `architect`.

## Dekripsi Broadcast

Broadcast dienkripsi dengan XOR:

```
ct ^ keystream(architect, len(ct))
```

Setelah token `architect` berhasil dibuat, ciphertext dibuka dan keluar payload:

```
[0xV0ID // COMMAND BROADCAST]
AUTH  : ARCHITECT
ORDER : stand down, the channel is burned
TOKEN : 0xV0ID{P4r7_2_15_2_C0MPL1C473D_Y4H?}
[EOT]
```

## Penyusunan Solve Script

`solve.py` melakukan semua tahap otomatis:

1. Recover `NODE_D` dari singular curve handshake.
2. Recover `AUTH_X` dari dua signature ECDSA terkait nonce.
3. Forge token architect dengan SHA-256 length extension.
4. Generate ulang keystream.
5. XOR ciphertext dan print plaintext.

## Cara Menjalankan

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Output:

```
[0xV0ID // COMMAND BROADCAST]
AUTH  : ARCHITECT
ORDER : stand down, the channel is burned
TOKEN : 0xV0ID{P4r7_2_15_2_C0MPL1C473D_Y4H?}
[EOT]
```

## Flag

```
0xV0ID{P4r7_2_15_2_C0MPL1C473D_Y4H?}
```


# BabyZKP

- **CTF:** No Hack No CTF 2026
- **Category:** Crypto
- **Service:** `chal.whale-tw.com:51337`
- **Difficulty:** Hard
- **Solved:** 2026-07-05

## Ringkasan

Service meminta kita membuktikan bahwa kita mengetahui secret `w` pada dua stage. Bentuk protokolnya mirip Schnorr:

```python
w = rng.next()
y = pow(2, w, p)

r = rng.next()
a = pow(2, r, p)
e = int(input("e="))
z = (r + e * w) % pp
```

Perbedaannya, response `z` direduksi dengan prime rahasia `pp`, bukan orde grup `p - 1`. Verifier juga membiarkan client memilih `e` berkali-kali dan menampilkan seluruh transcript `(a, z)`. Setelah beberapa query, client cukup mengirim `Y` dan menebak nilai `w` secara langsung.

Stage 1 memakai TLCG yang output-nya dipotong menjadi 512 bit. Stage 2 memakai Python `random.getrandbits(1024)`, yaitu MT19937. Kedua RNG tersebut dapat dipulihkan lewat kebocoran aljabar dari response `z`.

## Source audit

`challenge.py` membuat prime rahasia baru untuk setiap stage:

```python
pp = getPrime(1024)
w = rng.next()

r = rng.next()
a = pow(2, r, p)
e = int(input("e="))
z = (r + e * w) % pp
```

Syarat challenge hanya:

```python
if e.bit_length() < 1023 or e > p - 2 or e < 0:
    exit()
```

Jadi kita bebas memilih banyak nilai `e` selama ukurannya minimal 1023 bit.

Oracle dibatasi sebanyak:

```text
0x1337 = 4919 query
```

Stage 1 biasanya selesai dalam 3–4 query. Sisa query cukup untuk mengambil 4.000 sampel Stage 2.

---

## Stage 1 — recovery secret TLCG

Implementasi TLCG sebenarnya memiliki state 1024 bit, tetapi nilai yang dikembalikan selalu dipotong:

```python
class TLCG:
    MASK_BITS = 512
    MASK = (1 << 512) - 1

    def next(self):
        self.x = (self.A * self.x + self.C) % self.p
        return self.x & self.MASK
```

Akibatnya:

```text
0 <= w, r_i <= M
M = 2^512 - 1
```

### Memilih challenge berjarak tetap

Solver menggunakan:

```text
E = 2^1022
D = 2^510

e_i = E + iD
```

Nilai `E` mempunyai bit length 1023, sehingga lolos validasi server.

Untuk dua round berurutan yang tidak mengalami wrap modulo `pp`:

```text
z_i     = r_i     + e_i w
z_{i-1} = r_{i-1} + e_{i-1} w
```

Selisihnya:

```text
Δz = Δr + D w
```

Karena `r_i` hanya 512 bit:

```text
-M <= Δr <= M
```

Maka kandidat `w` berada pada interval:

```text
ceil((Δz - M) / D) <= w <= floor((Δz + M) / D)
```

Dengan `M ≈ 2^512` dan `D = 2^510`, interval tersebut hanya berisi sekitar delapan kandidat.

### Memvalidasi kandidat dengan commitment

Commitment memberi hubungan eksak:

```text
a_i / a_{i-1} = 2^(r_i-r_{i-1}) mod p
```

Untuk setiap kandidat `w`, nilai selisih nonce adalah:

```text
Δr = Δz - D w
```

Kandidat diterima jika:

```python
pow(2, delta_z - D * candidate, p) == a_i * inverse(a_prev, p) % p
```

Dua atau tiga pasangan transcript biasanya cukup untuk menyisakan satu kandidat. Pada solve remote, Stage 1 pulih setelah empat round.

Prime rahasia `pp` dapat menyebabkan wrap pada selisih tertentu. Step `D` dibuat jauh lebih kecil daripada `pp`, sehingga beberapa respons awal biasanya dapat dipakai sebelum terjadi crossing.

---

## Stage 2 — carry leakage dan state recovery MT19937

Stage 2 memakai:

```python
from random import getrandbits

class GetRandBits:
    def next(self):
        return getrandbits(1024)
```

Urutan output RNG adalah:

```text
w, r_0, r_1, r_2, ...
```

Semua query Stage 2 menggunakan challenge yang sama:

```text
e = 2^1022
```

Definisikan:

```text
s = e w mod pp
```

Response dapat ditulis sebagai:

```text
z_i = (r_i + s) mod pp
    = r_i + s - c_i pp
```

`c_i` adalah jumlah wrap modulo `pp`.

### Mengelompokkan carry

Dari commitment:

```text
a_i = 2^r_i mod p
```

Hitung:

```text
K_i = a_i * 2^(-z_i) mod p
```

Substitusi persamaan `z_i`:

```text
K_i = 2^(r_i-z_i) mod p
    = 2^(-s+c_i pp) mod p
```

Nilai `K_i` hanya bergantung pada carry `c_i`, bukan nonce `r_i`.

Karena:

```text
0 <= r_i < 2^1024
0 <= s < pp
2^1023 <= pp < 2^1024
```

maka:

```text
r_i + s < 3pp
```

Jadi carry hanya mungkin:

```text
c_i ∈ {0, 1, 2}
```

Seluruh transcript dapat dikelompokkan menjadi maksimal tiga cluster berdasarkan nilai `K_i`. Pada koneksi solve, hanya muncul dua cluster.

Label cluster belum langsung menunjukkan apakah carry-nya 0, 1, atau 2. Solver mencoba seluruh mapping yang mungkin.

### Hanya mengambil lima bit nonce

Dari:

```text
r_i = z_i - s + c_i pp
```

ambil modulo `2^k`:

```text
r_i mod 2^k = (z_i - s + c_i pp) mod 2^k
```

Solver memilih:

```text
k = 5
```

Unknown non-MT yang perlu ditebak hanya:

```text
pp mod 32
s mod 32
mapping cluster -> carry
```

Karena `pp` adalah prime ganjil:

```text
pp mod 32: 16 kemungkinan
s mod 32 : 32 kemungkinan
```

Untuk dua cluster, jumlah injective mapping ke `{0,1,2}` adalah:

```text
P(3,2) = 6
```

Total kandidat right-hand side:

```text
16 * 32 * 6 = 3072 kandidat
```

Ini cocok dengan log solver:

```text
[C] matrix 20000x19937 + 3072 candidates
```

### Membentuk sistem linear MT19937

MT19937 bersifat linear di atas `GF(2)`:

- transformasi twist hanya memakai shift, mask, dan XOR;
- tempering juga hanya memakai shift, mask, dan XOR;
- setiap bit output adalah kombinasi linear bit-bit state.

Walaupun array internal berisi `624 * 32 = 19968` bit, dimensi state efektif MT19937 adalah 19937 bit.

Satu pemanggilan `getrandbits(1024)` memakai 32 output 32-bit MT. Karena `w` diambil sebelum nonce pertama, low word tiap nonce berada pada posisi:

```text
32, 64, 96, 128, ...
```

Lima low bit dari setiap `r_i` memberi lima persamaan linear. Dengan 4.000 sampel:

```text
4000 * 5 = 20000 persamaan
```

Jumlah ini sedikit lebih besar daripada 19937 unknown state bit, sehingga matriks dapat mencapai full rank.

Helper C di dalam `solve.py`:

1. merepresentasikan setiap bit state sebagai bitset koefisien sepanjang 19937 bit;
2. menjalankan twist dan tempering secara simbolik;
3. mengambil lima bit output pada setiap posisi nonce;
4. menambahkan 3072 kandidat RHS sekaligus sebagai bitset tambahan;
5. menjalankan Gaussian elimination blok di `GF(2)`;
6. membuang kandidat RHS yang tidak konsisten;
7. melakukan back-substitution untuk kandidat yang tersisa.

Hasil remote:

```text
[C] elimination rank=19937 rows=20000
[C] valid candidate pairs=4 (returned 4)
```

### Validasi state dan mengambil secret

Beberapa kandidat low-bit dapat menghasilkan sistem yang konsisten. State penuh divalidasi dengan commitment asli:

```python
clone.setstate((3, state + (0,), None))
w = clone.getrandbits(1024)

for a, _ in records[:12]:
    r = clone.getrandbits(1024)
    assert pow(2, r, p) == a
```

Commitment `a_i = 2^r_i mod p` memeriksa seluruh 1024 bit nonce, sehingga false positive dari sistem lima-bit langsung gugur.

Setelah state benar ditemukan, output pertama clone adalah secret `w`, lalu solver mengirim:

```text
Y
w
```

---

## Catatan networking

Mengirim 4.000 query dalam satu `sendall()` menyebabkan TCP deadlock:

- client terus mengisi send buffer dengan input;
- server terus mengisi send buffer dengan transcript;
- kedua proses berhenti karena masing-masing belum membaca arah sebaliknya.

Solver membagi pipeline menjadi batch 64 round:

```text
e, N, e, N, ..., e
```

Client membaca seluruh output batch terlebih dahulu, lalu mengirim `N` untuk melanjutkan ke batch berikutnya. Cara ini tetap mengurangi round-trip tanpa memenuhi buffer TCP.

---

## Menjalankan solver

```bash
python3 solve.py chal.whale-tw.com 51337
```

Output utama:

```text
[+] Stage 1 recovered after 4 rounds
[*] requesting 4000 Stage 2 samples in batches of 64
[*] grouping Stage 2 carry classes
[+] Stage 2 carry clusters: 2
[*] recovering MT19937 from 4000 responses
[C] matrix 20000x19937 + 3072 candidates, 54.9 MiB
[C] elimination rank=19937 rows=20000
[C] valid candidate pairs=4 (returned 4)
[+] MT state valid, low(pp)=0x11, low(s)=0x1c, mapping=(0, 1)
NHNC{wow_i_am_wondering_about_if_there_are_any_in_the_wild_exploitable_zkp_like_this_:D}
```

## Flag

```text
NHNC{wow_i_am_wondering_about_if_there_are_any_in_the_wild_exploitable_zkp_like_this_:D}
```

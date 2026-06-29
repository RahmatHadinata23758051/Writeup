# needLe in a multivariate sekai

**Category:** Crypto  
**CTF:** SEKAI CTF 2026  
**Difficulty:** Hard  
**Flag:** `SEKAI{y0U_f0uND_th3_n33dL3!!!_https://youtu.be/Sloi-L5FHBY}`

## Ringkasan

Public key merupakan quadratic form 144 dimensi yang disamarkan dengan transformasi unimodular. Challenge juga memberikan 200 signature untuk pesan yang diketahui.

Signature tersebut bukan sekadar contoh. Setelah setiap sampel dinormalisasi dengan parameter Gaussian-nya, baris transformasi rahasia menjadi vektor-vektor pendek pada lattice transcript. LLL/BKZ dan `g6k` cukup untuk memulihkan transformasi unimodular, membuka kembali bentuk block matrix, lalu membuat signature valid untuk pesan `STAGE OF SEKAI`.

## File yang diberikan

```text
gen.py
server.py
sig.py
utils.py
pk.sobj
output.txt
```

`gen.py` membuat key pair dan membocorkan 200 signature:

```python
print([sig.sign(f"message {i}".encode()) for i in range(200)], file=f)
```

Server meminta satu signature untuk pesan tetap:

```python
signature = list(map(int, input("Signature: ").split()))
if sig.verify(b"STAGE OF SEKAI", signature):
    print(open("flag.txt").read())
```

Jadi targetnya adalah existential forgery untuk public key yang sama.

## Struktur skema

Parameter default:

```text
m = 128
k = 8
n = m + 2k = 144
B1 = 2^80
B0 = 2^40
```

Sebelum disamarkan, public quadratic form memiliki bentuk:

```text
        [ p I_8      0       M1^T ]
M   =   [   0      q I_8     M2^T ]
        [  M1       M2        M0  ]
```

`p` dan `q` adalah prime sekitar 80 bit. Matriks `M2` juga sengaja memiliki empat baris nol:

```python
for j in range(k):
    for i in range(4):
        M2[i, j] = 0
```

Keygen lalu membuat matriks unimodular `U` dari 40 lapisan permutasi dan row shear kecil:

```python
M_public = U.transpose() * M * U
```

Signer membentuk vektor tersembunyi `x`, kemudian mengeluarkan:

```python
signature = U_inv * x
```

Karena itu:

```text
s^T M_public s
= (U^-1 x)^T (U^T M U) (U^-1 x)
= x^T M x
= t
```

Untuk pesan `msg`, nilai targetnya adalah:

```python
t = int.from_bytes(b"\x01" + sha256(msg).digest(), "big")
```

## Kebocoran dari 200 signature

Misalkan setiap signature publik adalah kolom `s_i`. Dari proses signing:

```text
s_i = U^-1 x_i
```

maka:

```text
U s_i = x_i
```

Buat matriks transcript `S` berukuran `144 x 200`, dengan signature sebagai kolom. Untuk setiap baris rahasia `u_j` dari `U`:

```text
u_j S = (x_0[j], x_1[j], ..., x_199[j])
```

Koordinat tersembunyi `x_i[j]` diambil dari distribusi Gaussian dengan skala yang bisa dihitung dari pesan:

```python
u_i = round(sqrt(t_i // (2 * k * B1)))
```

Pesan-pesan pada transcript diketahui, yaitu `message 0` sampai `message 199`. Semua `t_i` dan `u_i` dapat dihitung ulang.

Saya menormalisasi setiap kolom transcript:

```python
R[j][i] = round((2**24) * S[j][i] / u_i)
```

Setelah normalisasi, baris `U` menghasilkan 200 sampel berukuran hampir seragam. `U` sendiri juga relatif kecil karena hanya dibuat dari permutasi dan shear dengan koefisien `-2..2`.

Gunakan embedding:

```text
B = [ R | I_144 ]
```

Untuk kombinasi integer `a`:

```text
a B = [aR | a]
```

Jika `a` adalah sebuah baris `U`, bagian `aR` menjadi satu koordinat tersembunyi dari 200 signature. Vektor tersebut jauh lebih pendek dibanding kombinasi acak. Blok identitas mencegah reducer memilih relasi transcript dengan koefisien sangat besar.

## Memulihkan transformasi unimodular

Reduksi dilakukan bertahap:

1. LLL pada embedding transcript untuk mendapat basis awal.
2. Bentuk Gram lokal `H = Y Y^T`, dengan `Y = T R` dan `T` sebagai transformasi yang sedang dilacak.
3. Jalankan beberapa pass BKZ block size 20 sampai 35 pada Gram matrix tersebut.
4. Bangun ulang embedding `[T R | I]`.
5. Jalankan `g6k` pump/sieving beberapa kali.

Potongan inti embedding:

```python
N = 144
K = 200
L = 24

raw = []
for j in range(N):
    row = []
    for i in range(K):
        row.append(round((signatures[i][j] << L) / gaussian_scales[i]))
    raw.append(row)

basis = [
    raw[i] + [1 if i == j else 0 for j in range(N)]
    for i in range(N)
]
```

Sesudah BKZ lokal, `g6k` dijalankan pada embedding yang sudah terkondisi:

```python
g = Siever(B, seed=1)
pump(
    g,
    dummy_tracer,
    0,
    N,
    104,
    down_sieve=False,
    start_up_n=30,
    saturation_error="weaken",
)
```

Pump diulang dengan seed berbeda. Pada hasil akhir, seluruh 144 vektor memiliki norm transcript sekitar 56–57 bit. Right block embedding memberi transformasi tambahan `R_g6k`, sehingga kandidat transformasi penuh adalah:

```text
U_recovered = R_g6k * T_BKZ
```

Kandidat yang benar memiliki determinant `-1`, sehingga tetap unimodular.

## Validasi recovery

Public matrix asli dipulihkan dengan:

```text
A = U_recovered^-T * M_public * U_recovered^-1
```

Hasilnya menunjukkan struktur yang tidak mungkin muncul secara kebetulan:

```text
p = 642378732174354748066531
q = 822744272433445084406581
```

Kedua nilai tersebut muncul tepat delapan kali pada diagonal. Selain itu ditemukan:

- dua kelompok diagonal berukuran delapan untuk block `p I_8` dan `q I_8`;
- tepat empat koordinat `x1` yang tidak memiliki coupling ke block `q`, sesuai `M2[:4, :] = 0`;
- 152 entri off-diagonal nol yang mengembalikan struktur block matrix;
- `det(U_recovered) = -1`.

Ini cukup untuk memastikan transformasi yang dipulihkan memang trapdoor asli, walaupun urutan dan tanda koordinat dapat berbeda.

## Menyusun ulang trapdoor

Dua prime dikenali dari nilai diagonal yang masing-masing berulang delapan kali. Block `q` dibedakan dari block `p` dengan mencari kelompok yang memiliki tepat empat baris `x1` tanpa coupling:

```python
def zero_rows(group):
    return [
        i for i in x_indices
        if all(A[i, j] == 0 for j in group)
    ]
```

Setelah koordinat diurutkan kembali menjadi:

```text
[p-block | q-block | x1-block]
```

matriks `M1`, `M2`, dan `M0` dapat diambil langsung dari block `A`.

## Membuat signature target

Signer asli direplikasi dengan trapdoor hasil recovery.

### 1. Hitung target

```python
message = b"STAGE OF SEKAI"
t = int.from_bytes(b"\x01" + sha256(message).digest(), "big")
```

### 2. Sampel `x1`

Ambil 128 bilangan Gaussian. Empat koordinat dikoreksi modulo `q`, lalu empat koordinat lain dikoreksi modulo `p`. Koreksi memakai minor `4 x 4` yang invertible:

```text
x1 * M2[:, q_selected] = 0 mod q
x1 * M1[:, p_selected] = 0 mod p
```

Fungsi `closest_congruent` memilih wakil kongruen yang paling dekat dengan sampel Gaussian awal.

### 3. Hitung residual

```text
c1 = x1 M1
c2 = x1 M2
```

Untuk kolom terpilih, pembagian berikut menjadi exact integer:

```text
o1 = c1[p_selected] / p
o2 = c2[q_selected] / q
```

Kemudian hitung residual target setelah kontribusi `x1` dan offset dikurangi.

### 4. Pecah residual menjadi `a p + b q`

Pilih `a` yang memenuhi:

```text
a = t0 * p^-1 mod q
```

Tambahkan kelipatan `q` sampai `a` dan:

```text
b = (t0 - a p) / q
```

keduanya non-negatif.

### 5. Four squares

Representasikan `a` dan `b` sebagai jumlah empat kuadrat:

```text
a = a0^2 + a1^2 + a2^2 + a3^2
b = b0^2 + b1^2 + b2^2 + b3^2
```

Empat nilai tersebut mengisi koordinat terpilih pada block `p` dan `q`. Vektor canonical menjadi:

```text
x = [d1 | d2 | x1]
```

Terakhir, ubah kembali ke koordinat publik:

```python
signature = U_recovered.inverse() * x
```

Signature hasil forge diverifikasi lokal dengan persamaan exact:

```python
assert signature * M_public * signature == t
```

## Solver final

Recovery lattice hanya perlu dilakukan satu kali karena public key dan pesan target tidak berubah. `solve.py` menyimpan signature hasil forge, memverifikasinya terhadap `pk.sobj`, lalu mengirim 144 integer ke service.

Jalankan:

```bash
python3 solve.py
```

Untuk hanya mengecek signature secara lokal:

```bash
python3 solve.py --verify-only
```

Jika `pk.sobj` tidak berada di direktori aktif:

```bash
python3 solve.py --skip-local-verify
```

Contoh output:

```text
[+] Local verification passed
SEKAI{y0U_f0uND_th3_n33dL3!!!_https://youtu.be/Sloi-L5FHBY}
<FLAG>SEKAI{y0U_f0uND_th3_n33dL3!!!_https://youtu.be/Sloi-L5FHBY}</FLAG>
```

## Flag

```text
SEKAI{y0U_f0uND_th3_n33dL3!!!_https://youtu.be/Sloi-L5FHBY}
```

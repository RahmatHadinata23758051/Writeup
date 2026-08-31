# Less is more Writeup

Target file berisi `challenge.py` dan `flag.enc`. Format `flag.enc` memakai magic `ASIS117\x04`, panjang big-endian, lalu body zlib + pickle. Setelah dibuka, isinya berisi:

- parameter publik `P, N, K, T, W`
- matriks dasar `g`
- 17 matriks publik
- kumpulan record signature
- `sealed`, yaitu flag yang di-XOR dengan pad dari `SHAKE256(b'o' + pack_key(secret_key))`

Kuncinya ada di record yang tidak normal. Pada signing normal, leaf yang kena challenge tidak dibuka. Di sini ada kondisi:

```python
if int.from_bytes(hashlib.sha256(b'v' + root).digest()[:2], 'big') % 100 < 72:
    f[target] = self.state[target]
```

Kalau `target` sedang kena challenge tetapi `f[target]` berubah menjadi 0, seed leaf tersebut ikut terbuka di path. Respons untuk leaf itu tetap ada di `rsp`. Ini membocorkan subset dari inverse permutation milik salah satu secret key.

## 1. Parsing capture

`flag.enc` dibaca dengan cara:

```python
raw = open('flag.enc', 'rb').read()
ln = struct.unpack('>I', raw[8:12])[0]
data = pickle.loads(zlib.decompress(raw[12:12 + ln]))
```

Jumlah record pada capture ini adalah **5963**. Flag terenkripsi panjangnya **54 byte**.

## 2. Mendeteksi record bocor

Challenge vector dihitung ulang dari `cmt`, `salt`, dan `msg` memakai fungsi `chal()`. Posisi target didapat dari serial message:

```python
target = (37 * serial + 11) % T
```

Token node pada path bisa dibalik karena hanya XOR dengan mask dari commitment:

```python
node = token ^ (sha256(b'm' + cmt)[:2] & 1023)
```

Untuk setiap record, ada dua kemungkinan state:

- `f` sama dengan indikator challenge normal.
- `f[target]` dibalik.

Solver menghitung cover tree untuk dua kemungkinan itu. Kalau hanya satu cover cocok dengan node-node di path, record dianggap bersih. Kalau dua-duanya cocok, record dilewati. Ini lebih aman daripada sok yakin, kegiatan favorit bug.

Record bocor terjadi saat:

```python
b[target] != 0 and f[target] == 0
```

Dari cover node yang memuat target, seed leaf diturunkan ulang dengan hash kiri atau kanan sampai mencapai leaf target. Lalu label-nya dicocokkan ke `rsp`:

```python
label = sha256(b't' + cmt + leaf_seed)[:8]
```

Dari situ kita mendapatkan:

- `V = take(leaf_seed, b'n', N, K)`
- `S` = response bitset
- kelas `key b[target] - 1`

## 3. Recover permutation

Untuk satu hit valid, signature membocorkan relasi:

```
S = { q[j] | j in V }
```

`q` adalah inverse permutation dari key untuk kelas tersebut.

Setiap kolom `j` punya pola keanggotaan pada semua subset `V`. Posisi `q[j]` punya pola keanggotaan yang sama pada semua subset `S`. Jadi permutation bisa dipulihkan dengan mencocokkan bit-signature.

Contoh idenya:

```python
sig_v[j] = bitmask record ketika j muncul di V
sig_s[i] = bitmask record ketika i muncul di S
q[j] = i jika sig_v[j] == sig_s[i]
```

Satu respons memang bisa dirusak oleh bagian ini:

```python
if int.from_bytes(hashlib.sha256(b'w' + root).digest()[:2], 'big') % 100 < 14:
    rsp[j][1] = bits(take(root, b'z', N, K))
```

Pada data ini, class 2 perlu membuang satu outlier, yaitu serial 5175. Setelah outlier dibuang, semua permutation 548 elemen pulih penuh.

## 4. Mencari matriks publik yang cocok

Ada 17 public matrix, tetapi hanya 7 yang real. Setelah permutation `p` didapat untuk setiap class, solver mencocokkannya dengan semua public matrix.

Matriks publik berasal dari:

```
public = red(g[:, p[j]] * inv(d[j]))
```

Karena `red()` hanya operasi baris, dua generator matrix tersebut row-equivalent dengan perbedaan scaling kolom. Untuk basis kolom pertama K, solver menghitung koordinat kolom sisa:

```
C = inv(G_basis) * G_other
D = inv(A_basis) * A_other
```

Untuk public matrix yang benar, berlaku:

```
D[r, c] / C[r, c] = lambda_c / lambda_basis_r
```

Artinya matrix rasio element-wise punya struktur rank-1. Public matrix yang benar memberi skor penuh `274 * 274 = 75076`. Yang salah hanya sekitar 600-an kecocokan acak.

Slot publik real yang ditemukan:

| Class | Slot |
|-------|------|
| 0     | 0    |
| 1     | 4    |
| 2     | 14   |
| 3     | 2    |
| 4     | 6    |
| 5     | 16   |
| 6     | 12   |

Dari rasio itu, solver memulihkan `d` dalam bentuk normalisasi yang sama dengan `pack_key()`, yaitu `d[j] / d[0]`.

## 5. Decrypt flag

Setelah `p` dan `d` untuk 7 key real pulih, key dipack ulang dengan format yang sama:

```python
for p, d in keys:
    for x in p:
        out += x.to_bytes(2, 'little')
    for x in d:
        out += x.to_bytes(2, 'little')
```

Pad dibuat ulang:

```python
pad = shake_256(b'o' + pack_key(keys)).digest(len(sealed))
flag = sealed ^ pad
```

Hasilnya:

```
ASIS{iZ_1tEr4t10n_5k1p_m4ke5_n0_1nn0c3nT_r3sPonse!!!?}
```

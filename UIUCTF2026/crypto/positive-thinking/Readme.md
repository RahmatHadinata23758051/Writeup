````md
# positive-thinking

## Ringkasan

Challenge ini menggunakan CKKS homomorphic encryption melalui TenSEAL. Server membuat secret acak 50-bit, mengenkripsinya, lalu memberikan public context dan ciphertext secret kepada user.

User dapat mengirim ciphertext lain ke oracle. Oracle akan mengevaluasi polynomial Chebyshev `T8(x)` terhadap ciphertext yang sudah dinormalisasi, kemudian hanya mengembalikan apakah hasil dekripsi bernilai positif atau tidak.

Flag diperoleh dengan mengubah output oracle `Positive` / `Not positive` menjadi oracle pembanding untuk mempersempit ruang secret. Setelah interval secret cukup kecil, solver mencoba kandidat satu per satu melalui prompt `Secret:` sampai secret yang benar ditemukan.

```text
uiuctf{s34rch1ng_th3_sp4c3_667f4c3d}
```

---

## File Challenge

File utama:

- `main.py` — source service challenge.
- `Dockerfile` — environment service.
- `nsjail.cfg` — konfigurasi jail service.

Bagian penting dari `main.py`:

```python
SECRET_BITS = 50
NORMALIZATION1 = 2**24
NORMALIZATION2 = 2**25
MAX_QUERIES = 100
```

Server membuat secret:

```python
secret = secrets.randbelow(2**SECRET_BITS)
```

Kemudian secret dienkripsi menggunakan CKKS:

```python
encrypted_secret = ts.ckks_vector(context, [secret])
```

Public context dibuat menjadi public dan dikirimkan kepada client bersama ciphertext secret:

```python
public_context = context.copy()
public_context.make_context_public()

print("Public context:")
print(base64.b64encode(public_context.serialize()).decode())

print("Encrypted value:")
print(base64.b64encode(encrypted_secret.serialize()).decode())
```

---

## Analisis Awal

Oracle menerima ciphertext dari user:

```python
blob = base64.b64decode(input("> "))
ciphertext = ts.ckks_vector_from(context, blob)
```

Ciphertext kemudian dinormalisasi dengan:

```python
2^24 * 2^25 = 2^49
```

Implementasinya:

```python
normalized = ciphertext * (1.0 / NORMALIZATION1) * (1.0 / NORMALIZATION2)
```

Setelah itu server mengevaluasi polynomial Chebyshev derajat 8:

```python
result = chebyshev8(normalized).decrypt()[0]
```

Output oracle hanya memberikan tanda hasil:

```python
print("Positive" if result > 0 else "Not positive")
```

Setelah setiap query, server meminta tebakan secret:

```python
guess = int(input("Secret: "))

if guess == secret:
    print(FLAG)
    raise SystemExit
```

Dengan demikian, target eksploitasi bukan mendekripsi ciphertext CKKS secara langsung, melainkan memanfaatkan tanda output `T8(...)` sebagai oracle untuk mencari nilai secret.

---

## 1. Analisis Polynomial Chebyshev

Polynomial yang digunakan adalah:

```text
T8(x) = 128x^8 - 256x^6 + 160x^4 - 32x^2 + 1
```

Akar `T8(x)` pada domain positif adalah:

```text
cos(7π/16)
cos(5π/16)
cos(3π/16)
cos(π/16)
```

Karena `T8(x)` hanya memiliki pangkat genap, polynomial ini merupakan fungsi genap:

```text
T8(x) = T8(-x)
```

Artinya, tanda output hanya bergantung pada nilai absolut input.

Jika kita mengirim ciphertext:

```text
Enc(secret - center)
```

maka server pada dasarnya mengevaluasi:

```text
T8((secret - center) / 2^49)
```

Tanda hasilnya memberikan informasi mengenai jarak:

```text
|secret - center|
```

terhadap akar-akar polynomial Chebyshev.

Informasi tersebut dapat digunakan untuk mempersempit ruang kandidat secret.

---

## 2. Parse Public Context dan Ciphertext

Solver terlebih dahulu membaca output awal server:

```text
Public context:
<base64 context>

Encrypted value:
<base64 ciphertext>
```

Kemudian context dan ciphertext dibangun kembali menggunakan TenSEAL:

```python
public_context = ts.context_from(base64.b64decode(ctx_b64))

enc_secret = ts.ckks_vector_from(
    public_context,
    base64.b64decode(enc_b64)
)
```

Dengan public context tersebut, kita tidak dapat mendekripsi secret secara langsung. Namun kita masih dapat melakukan operasi homomorphic terhadap ciphertext.

---

## 3. Narrowing dengan Oracle Chebyshev

Solver mengirim ciphertext berbentuk:

```text
enc_secret - center
```

Oracle kemudian menghitung:

```text
T8((secret - center) / 2^49)
```

dan hanya mengembalikan:

```text
Positive
```

atau:

```text
Not positive
```

Karena tanda polynomial berubah pada akar-akarnya, hasil tersebut memberikan informasi mengenai posisi secret relatif terhadap `center`.

Tahap ini digunakan untuk memperkecil candidate range dari:

```text
0 ... 2^50 - 1
```

menjadi interval yang jauh lebih kecil.

---

## 4. Masalah CKKS Noise

CKKS merupakan skema homomorphic encryption yang bersifat approximate.

Akibatnya, hasil evaluasi polynomial tidak selalu tepat di sekitar akar. Jika input berada sangat dekat dengan boundary, noise CKKS dapat menyebabkan hasil yang seharusnya positif menjadi negatif atau sebaliknya.

Karena itu, narrowing tidak boleh menganggap boundary sebagai titik yang benar-benar presisi.

Diperlukan guard di sekitar boundary untuk menghindari keputusan yang terlalu dekat dengan noise.

---

## 5. Amplified Comparison

Untuk tahap akhir, solver menggunakan teknik amplification.

Tujuannya adalah memperbesar selisih:

```text
secret - lo
```

sebelum ciphertext dimasukkan ke oracle.

Secara konsep kita ingin membuat:

```text
Enc(2^shift * (secret - lo))
```

Namun melakukan scalar multiplication dengan angka yang sangat besar dapat menghabiskan level ciphertext CKKS sebelum polynomial dievaluasi.

Sebagai gantinya, solver menggunakan repeated addition:

```python
ct = enc_secret - float(base)

for _ in range(shift):
    ct = ct + ct
```

Setiap operasi:

```text
ct = ct + ct
```

menggandakan nilai ciphertext tanpa menggunakan multiplication level seperti operasi perkalian ciphertext.

Dengan demikian, perbedaan kecil antara secret dan boundary dapat diperbesar sebelum masuk ke oracle.

---

## 6. Mengubah Oracle Menjadi Comparison Oracle

Setelah amplification, kita dapat menggunakan tanda `T8(x)` sebagai comparison oracle pada range tertentu.

Secara konseptual:

```text
Positive
    ->
secret berada pada satu sisi boundary

Not positive
    ->
secret berada pada sisi lainnya
```

Dengan memilih `base` dan faktor amplification yang sesuai, solver dapat melakukan binary search terhadap secret.

Karena CKKS approximate, solver tetap menggunakan guard untuk menghindari area yang terlalu dekat dengan akar polynomial.

---

## 7. Brute Force Kandidat Akhir

Setelah narrowing selesai, solver tidak perlu lagi melakukan query polynomial secara agresif.

Jika interval kandidat sudah cukup kecil, lebih aman untuk langsung mencoba kandidat satu per satu pada prompt:

```text
Secret:
```

Pada run yang berhasil, interval akhir adalah:

```text
[256509943364076, 256509943364116]
```

Jumlah kandidat:

```text
41
```

Secret yang benar ditemukan pada percobaan ke-28:

```text
256509943364103
```

Server kemudian mengeluarkan:

```text
uiuctf{s34rch1ng_th3_sp4c3_667f4c3d}
```

---

## 8. Alur Eksploitasi

```text
                 Public CKKS Context
                         |
                         v
                 Encrypted Secret
                         |
                         v
              Kirim ciphertext query
                         |
                         v
              T8((secret-center)/2^49)
                         |
                         v
                 Positive / Not positive
                         |
                         v
                  Narrowing awal
                         |
                         v
                Amplified comparison
                         |
                         v
                 Interval kecil
                         |
                         v
                 Brute-force kandidat
                         |
                         v
                    Secret benar
                         |
                         v
               FLAG: uiuctf{...}
```

---

## 9. Solve Script

Solver melakukan langkah berikut:

1. Connect ke service remote melalui SSL.
2. Parse `Public context`.
3. Parse `Encrypted value`.
4. Load context dan ciphertext secret menggunakan TenSEAL.
5. Menggunakan oracle `Positive` / `Not positive` untuk narrowing awal.
6. Menggunakan amplified comparison dengan repeated addition.
7. Mengurangi candidate interval hingga cukup kecil.
8. Mencoba kandidat satu per satu melalui prompt `Secret:`.
9. Mengekstrak flag dari output server.

---

## 10. Cara Menjalankan

Aktifkan virtual environment:

```bash
source /home/nata/ctf_env/bin/activate
```

Atau gunakan environment lain yang sudah memiliki TenSEAL.

Install dependency jika belum tersedia:

```bash
pip install tenseal
```

Jalankan solver:

```bash
python3 solve.py
```

Jika tahap akhir terlalu dekat dengan noise CKKS, guard dapat dinaikkan:

```bash
GUARD=32 python3 solve.py
```

atau:

```bash
GUARD=128 python3 solve.py
```

Nilai guard yang lebih besar membuat solver lebih konservatif terhadap boundary polynomial.

---

## 11. Hasil

Solver berhasil mendapatkan secret:

```text
256509943364103
```

Kemudian server memberikan flag:

```text
uiuctf{s34rch1ng_th3_sp4c3_667f4c3d}
```

---

## Flag

```text
uiuctf{s34rch1ng_th3_sp4c3_667f4c3d}
```
````

Siap bro. Berikut versi `.md` yang sudah dirapikan dan siap disimpan sebagai `laporan_analisis_kerentanan.md`.

# Laporan Analisis Kerentanan: A Million Messages

**Kategori:** Cryptography
**Vulnerability:** RSA PKCS#1 v1.5 Padding Oracle (Bleichenbacher 1998 / BB98)
**Tingkat Kesulitan:** Menengah – Mahir

## 1. Tinjauan Umum

Tantangan **"A Million Messages"** mensimulasikan sebuah server yang mengimplementasikan protokol dekripsi RSA. Pengguna diberikan akses ke soket TCP yang secara dinamis menghasilkan parameter kunci publik berupa **Modulus (`N`)**, **Eksponen (`E`)**, serta sebuah **Ciphertext (`C`)** yang menyimpan pesan rahasia (*flag*).

Interaksi dengan server mengungkapkan bahwa aplikasi mengembalikan pesan kesalahan spesifik (`BAD`) ketika menerima ciphertext yang hasil dekripsinya tidak memiliki struktur padding PKCS#1 v1.5 yang valid.

Perilaku tersebut menciptakan kerentanan **Padding Oracle**, yang memungkinkan penyerang merekonstruksi plaintext asli tanpa perlu mengetahui private key (`d`) atau melakukan faktorisasi terhadap modulus `N`.

---

## 2. Pengumpulan Informasi dan Analisis Permukaan

Koneksi awal ke:

```text
chal.thjcc.org:12003
```

memberikan parameter berikut:

| Parameter             | Nilai               |
| --------------------- | ------------------- |
| Modulus (`N`)         | 512-bit (64 bytes)  |
| Public Exponent (`E`) | `65537` (`0x10001`) |
| Ciphertext (`C`)      | 512-bit             |

Modulus `N` dihasilkan secara acak pada setiap sesi koneksi.

Karakteristik dinamis tersebut mencegah penggunaan metode kriptanalisis luring seperti faktorisasi menggunakan **General Number Field Sieve (GNFS)** melalui CADO-NFS atau pencarian pada basis data seperti FactorDB.

Oleh karena itu, serangan interaktif secara langsung terhadap server merupakan rute eksploitasi yang valid.

### Validasi Input

Server mengharuskan payload memiliki format:

* Tepat **128 karakter hexadecimal**
* Merepresentasikan **64 bytes**
* Diakhiri karakter newline (`\n`)

Kegagalan memenuhi format tersebut dapat menyebabkan server memutus koneksi akibat *exception handling* yang tidak memadai.

---

## 3. Landasan Teori Kriptanalisis: Bleichenbacher 1998

Kerentanan berakar pada cara standar **RSA PKCS#1 v1.5** memformat data sebelum operasi matematis RSA dilakukan.

### 3.1. Struktur Padding PKCS#1 v1.5

Untuk modulus RSA dengan panjang `k` byte, plaintext sebelum operasi RSA memiliki struktur:

```text
0x00 || 0x02 || PS || 0x00 || M
```

dengan:

* `0x00` dan `0x02`: penanda blok untuk mode enkripsi.
* `PS`: *Padding String* yang terdiri dari byte acak non-zero dengan panjang minimal 8 byte.
* `0x00`: byte separator.
* `M`: plaintext atau pesan sebenarnya.

Dalam representasi integer, blok yang memenuhi dua byte awal `0x00 0x02` berada pada interval:

$$
2B \leq m < 3B
$$

dengan:

$$
B = 2^{8(k-2)}
$$

---

### 3.2. Sifat Homomorfik Multiplikatif RSA

RSA murni memiliki sifat homomorfik multiplikatif.

Jika:

$$
C = m^E \pmod N
$$

maka penyerang dapat membentuk ciphertext baru:

$$
C' = C \cdot s^E \pmod N
$$

yang ketika didekripsi menghasilkan:

$$
m' = m \cdot s \pmod N
$$

Secara lengkap:

$$
C' = C \cdot s^E
$$

$$
= m^E \cdot s^E
$$

$$
= (m \cdot s)^E \pmod N
$$

Dengan demikian, penyerang dapat memanipulasi plaintext hasil dekripsi secara tidak langsung tanpa mengetahui private key.

---

### 3.3. Algoritma Pencarian Interval BB98

Server bertindak sebagai **oracle** berdasarkan validitas padding.

Jika ciphertext hasil manipulasi menghasilkan respons `BAD`, maka nilai:

$$
m \cdot s \pmod N
$$

berada di luar interval PKCS#1 v1.5 yang valid.

Sebaliknya, apabila server memberikan respons non-`BAD`, penyerang memperoleh informasi bahwa:

$$
2B \leq (m \cdot s \pmod N) < 3B
$$

Informasi satu-bit tersebut dapat digunakan secara iteratif untuk mempersempit himpunan kemungkinan nilai plaintext.

Algoritma Bleichenbacher 1998 secara umum terdiri dari beberapa fase:

1. **Blinding**
   Dilakukan apabila ciphertext awal belum diketahui sebagai ciphertext yang memenuhi format PKCS#1 v1.5.

2. **Pencarian awal (`s₁`)**
   Mencari nilai integer `s₁` yang menghasilkan plaintext dengan struktur padding valid.

3. **Pencarian lanjutan**
   Setelah `s₁` ditemukan, pencarian nilai `s` berikutnya dapat dibatasi pada rentang yang semakin sempit.

4. **Penyempitan interval**
   Berdasarkan nilai `s` yang valid, kemungkinan nilai plaintext dihitung ulang dan interval kandidat dipersempit.

5. **Konvergensi**
   Iterasi dilanjutkan hingga interval kandidat hanya menyisakan satu nilai plaintext.

---

## 4. Metodologi Serangan dan Eksekusi

### 4.1. Kendala Teknis dan Optimasi I/O

Implementasi awal menggunakan framework **pwntools** mengalami kegagalan pada fase pencarian awal.

Fase tersebut membutuhkan sejumlah besar request ke server. Overhead logging dan pengelolaan objek koneksi menyebabkan penggunaan memori meningkat secara signifikan hingga proses Python dihentikan oleh **Out-Of-Memory (OOM) Killer**.

Untuk mengatasi masalah tersebut, implementasi kemudian ditulis ulang menggunakan modul `socket` bawaan Python.

Komunikasi I/O menggunakan buffer minimal melalui objek:

```python
makefile("rw", buffering=1)
```

Pendekatan tersebut mengurangi overhead yang tidak diperlukan dan memungkinkan proses pencarian berjalan lebih stabil.

---

### 4.2. Potongan Logika Eksploitasi

Konstanta awal dan interval kandidat dapat dihitung sebagai berikut:

```python
k = (N.bit_length() + 7) // 8
B = 2 ** (8 * (k - 2))

M = [(2 * B, 3 * B - 1)]
s_val = 1
```

Pencarian awal terhadap `s₁`:

```python
s_val = ceil_div(N, 3 * B)

while True:
    c_test = (C * pow(s_val, E, N)) % N

    if oracle(c_test):
        break

    s_val += 1
```

Setelah nilai `s` yang valid ditemukan, interval kandidat diperbarui:

```python
M_new = []

for a, b in M:
    r_min = ceil_div(a * s_val - 3 * B + 1, N)
    r_max = (b * s_val - 2 * B) // N

    for r_val in range(r_min, r_max + 1):
        lower = max(
            a,
            ceil_div(2 * B + r_val * N, s_val)
        )

        upper = min(
            b,
            (3 * B - 1 + r_val * N) // s_val
        )

        if lower <= upper:
            M_new.append((lower, upper))
```

Interval yang dihasilkan kemudian diurutkan dan digabungkan (*merge*) untuk menghilangkan irisan yang tumpang tindih.

---

## 4.3. Analisis Eksekusi

Skrip hasil optimasi dapat berjalan dengan penggunaan memori yang jauh lebih stabil.

Statistik eksekusi:

| Parameter         | Hasil                             |
| ----------------- | --------------------------------- |
| Metode I/O        | Python `socket`                   |
| Ukuran modulus    | 512-bit                           |
| `E`               | `65537`                           |
| Penemuan `s₁`     | Iterasi ke-20.785                 |
| Nilai `s₁`        | `20785`                           |
| Konvergensi akhir | Interval memiliki selisih `0` bit |

Nilai pivot pertama yang menghasilkan plaintext dengan padding valid ditemukan pada:

$$
s_1 = 20785
$$

Setelah nilai tersebut ditemukan, proses penyempitan interval berlangsung jauh lebih cepat. Setiap iterasi mengurangi ruang kemungkinan plaintext hingga akhirnya hanya tersisa satu nilai absolut.

---

## 5. Hasil Dekripsi

Hasil akhir algoritma berupa sebuah integer yang merepresentasikan plaintext ter-*encode* dalam bentuk blok PKCS#1 v1.5.

Setelah dikonversi kembali menjadi byte, diperoleh:

```text
\x02O6\xa9gj\x923\x96A\xc9\xd7\x19\xad\xe7\x8f\xe8M\r\x00THJCC{bl31chenb4ch3r_st1ll_3ats_pkcs1_v1_5}
```

Struktur byte tersebut sesuai dengan format padding yang diharapkan.

Secara konseptual, strukturnya adalah:

```text
\x02
    └── Padding String
        └── \x00
            └── Message / Flag
```

Byte `\x00` di awal blok tidak terlihat pada representasi tertentu karena konversi integer-ke-byte dapat menghilangkan leading zero.

Setelah padding dan separator dipotong hingga byte `\x00`, diperoleh plaintext:

```text
THJCC{bl31chenb4ch3r_st1ll_3ats_pkcs1_v1_5}
```

### Flag

```text
THJCC{bl31chenb4ch3r_st1ll_3ats_pkcs1_v1_5}
```

---

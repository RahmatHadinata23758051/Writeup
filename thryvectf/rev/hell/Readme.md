Kalau mau dijadikan writeup `.md` yang lebih enak dibaca dan nggak terlalu terasa seperti dump analisis, bisa dibuat seperti ini:

# Hell

## Flag

```text
Thryve{m4th_m4dn3ss}
```

## Ringkasan

Challenge `Hell` adalah reverse engineering terhadap binary ELF 64-bit PIE yang sudah di-strip.

Program menerima flag melalui `argv`, kemudian mengecek format dasarnya sebelum memvalidasi 12 karakter di dalam `{...}`. Bagian validasi ternyata menggunakan operasi sederhana berupa XOR, penjumlahan, dan perkalian modulo 256.

Walaupun binary terlihat cukup berisik karena ada fungsi yang penuh operasi bitwise, bagian pentingnya justru cukup sederhana setelah alur validasinya ditemukan.

---

## 1. File Challenge

Binary yang diberikan:

```text
rev_hell: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

Binary menggunakan libc standar. Beberapa import yang terlihat antara lain:

```text
strlen
strncmp
strncpy
printf
puts
```

Karena binary sudah **stripped**, nama fungsi asli tidak tersedia. Jadi analisis dilakukan berdasarkan alamat fungsi, penggunaan register, dan alur pemanggilan.

---

## 2. Analisis Awal

Langkah pertama adalah melihat string yang masih tersimpan di binary.

Dengan `strings`, ditemukan beberapa string yang cukup membantu:

```text
Usage: %s [flag]
Thryve{
Invalid format!
Access Granted!
Access Denied!
```

Dari sini sudah terlihat bahwa program memang meminta sebuah flag sebagai argument dan memiliki dua kemungkinan hasil:

```text
Access Granted!
Access Denied!
```

Prefix flag juga diketahui:

```text
Thryve{
```

Selain itu, pada section `.data` terdapat 12 byte yang terlihat seperti data target:

```text
67 f8 71 ec 32 37 3a b7 70 19 47 f6
```

Jumlahnya tepat 12 byte, sama dengan panjang isi flag yang nantinya divalidasi.

---

## 3. Analisis `main`

Fungsi `main` ditemukan di sekitar:

```text
0x1312
```

Walaupun binary stripped, alurnya masih cukup mudah diikuti.

Secara garis besar, program melakukan:

1. Memastikan `argc == 2`.
2. Mengecek panjang argument menggunakan `strlen`.
3. Panjang input harus `0x14`, yaitu 20 byte.
4. Tujuh karakter pertama harus sama dengan `Thryve{`.
5. Karakter terakhir harus `}`.
6. Dua belas byte di antara `{` dan `}` disalin ke buffer lokal.
7. Buffer tersebut kemudian masuk ke fungsi validasi.

Struktur inputnya berarti:

```text
Thryve{............}
       ^^^^^^^^^^^^
        12 chars
```

Total panjangnya:

```text
7 + 12 + 1 = 20
```

Jadi kita hanya perlu memecahkan **12 karakter di tengah**.

---

## 4. Fungsi yang Menyesatkan

Ada sebuah fungsi di sekitar:

```text
0x1179
```

Fungsi ini terlihat cukup rumit. Isinya banyak operasi bitwise dan manipulasi accumulator sehingga sekilas terlihat seperti bagian utama dari algoritma.

Namun setelah diperhatikan lebih lanjut, fungsi tersebut tidak mengubah input yang sedang divalidasi dan nilai return-nya juga tidak digunakan sebagai hasil pengecekan.

Dengan kata lain, fungsi tersebut lebih mirip **noise/obfuscation** daripada bagian penting dari validasi flag.

Bagian yang benar-benar menentukan benar atau salahnya flag berada di:

```text
0x122d
```

Di sinilah kita bisa melihat persamaan yang digunakan checker.

---

## 5. Membongkar Algoritma Validasi

Misalkan 12 karakter isi flag kita beri nama:

```text
s[0], s[1], ..., s[11]
```

Checker mengambil tiga karakter secara cyclic untuk setiap posisi:

```text
a = s[i]
b = s[(i + 1) % 12]
c = s[(i + 2) % 12]
```

Kemudian menghitung:

```text
calc = 3 * ((a ^ b) + c)
```

Hasil tersebut hanya dibandingkan pada **8 bit terendah** dengan target yang tersimpan di `.data`.

Targetnya:

```text
67 f8 71 ec 32 37 3a b7 70 19 47 f6
```

Karena hanya byte rendah yang dibandingkan, operasi tersebut secara efektif bekerja modulo 256:

```text
3 * ((a ^ b) + c) mod 256
```

---

## 6. Membalik Perkalian Modulo 256

Kita punya persamaan:

```text
3 * X ≡ target (mod 256)
```

Karena `3` relatif prima dengan `256`, perkalian tersebut memiliki invers modulo 256.

Invers dari `3` adalah:

```text
171
```

karena:

```text
3 × 171 = 513
513 mod 256 = 1
```

Jadi target bisa dibalik dengan:

```text
D[i] = target[i] * 171 mod 256
```

Setelah itu persamaan checker berubah menjadi:

```text
(s[i] ^ s[i+1]) + s[i+2] = D[i] mod 256
```

dan kita bisa langsung menyelesaikan karakter berikutnya:

```text
s[i+2] = D[i] - (s[i] ^ s[i+1]) mod 256
```

Ini bagian yang membuat challenge jauh lebih sederhana.

---

## 7. Kenapa Cukup Brute Force Dua Karakter?

Untuk mendapatkan `s[2]`, kita hanya perlu mengetahui:

```text
s[0]
s[1]
```

Setelah dua karakter pertama diketahui, karakter ketiga langsung bisa dihitung:

```text
s[2] = D[0] - (s[0] ^ s[1]) mod 256
```

Kemudian karakter keempat:

```text
s[3] = D[1] - (s[1] ^ s[2]) mod 256
```

dan seterusnya.

Jadi seluruh string 12 karakter dapat dibangun secara berurutan hanya dari dua karakter awal.

Secara umum:

```text
s[i+2] = D[i] - (s[i] ^ s[i+1]) mod 256
```

Kita cukup mencoba kemungkinan `s[0]` dan `s[1]`, lalu membiarkan recurrence menghasilkan 10 karakter sisanya.

Karena flag CTF biasanya menggunakan karakter printable, pencarian bisa dibatasi ke charset printable yang masuk akal.

---

## 8. Solver

Solver melakukan proses berikut:

1. Memasukkan target 12 byte.
2. Menghitung invers `3 mod 256`.
3. Mengubah target menjadi nilai `D`.
4. Brute force dua karakter pertama.
5. Menghasilkan karakter berikutnya menggunakan recurrence.
6. Memastikan semua karakter berada dalam charset yang diinginkan.
7. Memvalidasi ulang seluruh 12 persamaan cyclic.
8. Jika semuanya cocok, mencetak flag.

Contoh implementasinya:

```python
from itertools import product
import string

target = bytes.fromhex(
    "67 f8 71 ec 32 37 3a b7 70 19 47 f6"
)

inv3 = pow(3, -1, 256)

# Balik perkalian 3 modulo 256
D = [(x * inv3) & 0xff for x in target]

charset = string.ascii_letters + string.digits + "_-{}"

for a, b in product(
    (ord(c) for c in charset),
    repeat=2
):
    s = [a, b]

    # Bangun karakter berikutnya
    for i in range(10):
        nxt = (D[i] - (s[i] ^ s[i + 1])) & 0xff
        s.append(nxt)

    # Semua karakter harus printable
    if not all(32 <= x <= 126 for x in s):
        continue

    # Validasi ulang semua persamaan secara cyclic
    ok = True

    for i in range(12):
        a = s[i]
        b = s[(i + 1) % 12]
        c = s[(i + 2) % 12]

        calc = (3 * ((a ^ b) + c)) & 0xff

        if calc != target[i]:
            ok = False
            break

    if ok:
        inner = bytes(s).decode()
        print(f"Thryve{{{inner}}}")
```

Hasilnya:

```text
Thryve{m4th_m4dn3ss}
```

---

## 9. Dynamic Validation

Setelah mendapatkan kandidat, langkah berikutnya adalah memastikan bahwa binary benar-benar menerimanya.

Binary dijalankan dengan:

```bash
./rev_hell 'Thryve{m4th_m4dn3ss}'
```

Output:

```text
Access Granted!
```

Sebagai pembanding, input yang salah:

```bash
./rev_hell 'Thryve{wrong_______}'
```

menghasilkan:

```text
Access Denied!
```

Jadi hasil solve sudah terkonfirmasi langsung oleh binary.

---

## 10. Kesimpulan

Challenge ini awalnya terlihat cukup intimidating karena binary stripped dan terdapat fungsi yang penuh operasi bitwise yang kelihatannya seperti obfuscation.

Tapi setelah alur `main` diikuti, ternyata bagian pentingnya hanya validasi 12 byte menggunakan:

```text
3 * ((a ^ b) + c) mod 256
```

Kunci untuk membongkarnya adalah menyadari bahwa `3` mempunyai invers modulo 256:

```text
3⁻¹ ≡ 171 (mod 256)
```

Setelah perkalian tersebut dibalik, kita mendapatkan recurrence:

```text
s[i+2] = D[i] - (s[i] ^ s[i+1]) mod 256
```

Sehingga cukup melakukan brute force terhadap dua karakter pertama. Sepuluh karakter berikutnya bisa dihitung langsung.

Hasil akhirnya:

```text
Thryve{m4th_m4dn3ss}
```

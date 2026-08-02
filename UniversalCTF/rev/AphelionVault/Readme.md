# Aphelion Vault Writeup

## Ringkasan

Challenge menyediakan sebuah binary ELF 64-bit bernama `aphelion_vault` yang meminta sebuah **alignment phrase** sepanjang **24 karakter**.

Frasa tersebut tidak disimpan sebagai string utuh di dalam binary. Sebagai gantinya, program membangun tiga buah array target dari section khusus `.vault`, kemudian memvalidasi input dalam tiga tahap. Apabila seluruh validasi berhasil, input yang benar digunakan sebagai kunci untuk mendekripsi ciphertext yang juga tersimpan pada section `.vault`.

Hasil reversing:

```text
Alignment phrase:
nereid-apsis-vector-4912

Flag:
uctf{n3r31d_4ps1s_v4ult_4l1gn3d}
```

---

# Informasi Binary

```
README.txt
aphelion_vault
```

```text
ELF 64-bit LSB executable
x86-64
Dynamically linked
Stripped
```

SHA-256:

```text
9234521fe1162c46ca5d85846046b9a5404c224e8753b51b606e603c6634fae8
```

Binary merupakan **ET_EXEC**, sehingga bukan PIE.

Alamat penting:

| Item | Address |
|------|---------|
| Entry Point | `0x401420` |
| Main | `0x4010c0` |

---

# Analisis Awal

Output `strings` hanya menampilkan pesan antarmuka.

```text
Nereid aphelion vault maintenance client
Recovered handshake requires the correct alignment phrase.
Alignment phrase:
Trajectory rejected.
Vault alignment accepted.
```

Tidak ditemukan alignment phrase maupun flag dalam bentuk plaintext.

---

# Analisis Section

Daftar section menunjukkan adanya section nonstandar:

```text
.vault
Address : 0x4020c0
Offset  : 0x20c0
Size    : 0x40
```

Isi section:

```text
4e524430013627003720b1c48de4b31b
f6af2bdac24a625a6e47af1720000000
9b12a20be8c4e2edc94e2358fb44aee6
57e67499615bdf0f8a4df71aade98552
```

Layout data:

| Offset | Fungsi |
|---------|--------|
| `0x00-0x03` | Marker `NRD0` |
| `0x04-0x1B` | Data pembentuk target validasi |
| `0x20-0x3F` | Ciphertext flag |

Empat byte pertama (`NRD0`) digunakan sebagai marker untuk menemukan section `.vault`, sedangkan 32 byte terakhir merupakan ciphertext yang baru dapat didekripsi setelah alignment phrase berhasil dipulihkan.

---

# Analisis Static

Program membaca input menggunakan `fgets()`.

```asm
call fgets
```

Karakter newline dihapus menggunakan `strcspn()`.

Selanjutnya panjang input diperiksa.

```asm
40114a: call strlen
40114f: cmp  rax, 0x18
```

Input wajib memiliki panjang tepat **24 karakter**.

Kemudian setiap karakter divalidasi berada pada rentang ASCII printable.

```asm
4011d2: lea edi,[rcx-0x21]
4011d5: cmp dil,0x5d
4011d9: jbe ...
```

Artinya hanya karakter:

```text
0x21 ('!')
hingga
0x7e ('~')
```

yang diterima.

---

# Penyusunan Target

Loop pada alamat `0x401210` membentuk tiga buah array target berukuran delapan byte.

## Target A

```text
target_a[i] =
vault[4+i] ^
(0xA5 - 9*i)
```

---

## Target B

```text
target_b[i] =
((vault[12+i] - 11*i - 7) & 0xff)
^ 0x5c
```

---

## Target C

```text
target_c[i] =
ror8(vault[20+i],1)
^
(0x33 + 4*i)
```

Ketiga array tersebut dipakai pada tiga loop validasi berikutnya.

---

# Analisis Dynamic

Percobaan menggunakan berbagai input acak selalu menghasilkan:

```text
Trajectory rejected.
```

Setelah alignment phrase berhasil direkonstruksi, binary memberikan output:

```bash
$ printf 'nereid-apsis-vector-4912\n' | ./aphelion_vault

Nereid aphelion vault maintenance client
Recovered handshake requires the correct alignment phrase.
Alignment phrase:
Vault alignment accepted.

uctf{n3r31d_4ps1s_v4ult_4l1gn3d}
```

Hal ini membuktikan bahwa frasa dan flag memang berasal dari mekanisme validasi asli program.

---

# Rekonstruksi Alignment Phrase

Alignment phrase divalidasi dalam tiga tahap.

---

## Tahap 1

Delapan karakter pertama diproses menggunakan transformasi:

```text
rol8(
    (input[i] ^
    (0x21 + 13*i))
    +
    (3 + 7*i),
    1
)
==
target_a[i]
```

Transformasi tersebut dibalik menjadi:

```text
input[i] =
(
ror8(target_a[i],1)
-
(3+7*i)
)
^
(0x21+13*i)
```

Hasil:

```text
nereid-a
```

---

## Tahap 2

Delapan karakter berikutnya menggunakan karakter dari blok pertama.

```text
rol8(
(
input[8+i]
+
index
+
0x14
+
input[index&7]
)
^
(0x5a-3*i),
2
)
==
target_b[i]
```

Dengan membalik transformasi tersebut diperoleh:

```text
nereid-apsis-vec
```

---

## Tahap 3

Blok terakhir menggunakan referensi silang terhadap blok kedua.

```text
rol8(
(
input[15-i]
^
input[16+i]
)
+
5*i
+
0x33,
3
)
==
target_c[i]
```

Hasil akhir alignment phrase:

```text
nereid-apsis-vector-4912
```

---

# Dekripsi Flag

Setelah validasi selesai, alignment phrase dijadikan kunci sepanjang 24 byte.

Program kemudian mendekripsi ciphertext pada `.vault+0x20`.

Algoritma:

```python
for i in range(32):

    out = (
        key[i % 24]
        + 0x17
        + 0x11*i
    ) & 0xff

    out ^= ciphertext[i]
    out ^= (0xA9 - 3*i) & 0xff
    out ^= rol8(key[(7 + 5*i) % 24],1)
```

Output dari loop tersebut merupakan string flag.

---

# Penyusunan Solve Script

`solve.py` melakukan empat tahap utama.

1. Membaca binary dan mencari marker `NRD0`.
2. Mengekstrak seluruh isi section `.vault`.
3. Membalik tiga tahap validasi untuk memperoleh alignment phrase.
4. Menggunakan alignment phrase sebagai kunci untuk mendekripsi ciphertext.

Sebagai validasi tambahan, script juga menjalankan binary menggunakan alignment phrase yang telah diperoleh dan memastikan hasilnya identik dengan proses dekripsi.

---

# Cara Menjalankan

```bash
cd /mnt/data/aphelion_vault_challenge

python3 solve.py
```

---

# Output

```text
Alignment phrase:
nereid-apsis-vector-4912

Flag:
uctf{n3r31d_4ps1s_v4ult_4l1gn3d}

Validasi binary:

Nereid aphelion vault maintenance client
Recovered handshake requires the correct alignment phrase.
Alignment phrase:
Vault alignment accepted.

uctf{n3r31d_4ps1s_v4ult_4l1gn3d}
```

---

# Flag

```text
uctf{n3r31d_4ps1s_v4ult_4l1gn3d}
```

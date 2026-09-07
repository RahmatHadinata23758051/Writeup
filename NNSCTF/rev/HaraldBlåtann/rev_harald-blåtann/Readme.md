# Writeup CTF: Harald Blåtann

- **Kategori:** Reverse Engineering / Embedded Security
- **Tingkat Kesulitan:** Medium
- **Artefak:** `harald-blatann.hex`
- **Platform:** nRF / Zephyr BLE
- **Flag:** `NNS{w1r3lessly_s3nt_4nd_ch3ck3d_by_th3_p0w3r_0f_k1ng_bl4t4nn}`

---

# 1. Deskripsi Tantangan

Challenge memberikan sebuah firmware dalam format Intel HEX untuk target:

```
nRF / Zephyr BLE
```

Firmware tidak melakukan validasi flag melalui:

- stdin
- serial console
- command line

Sebaliknya, validasi dilakukan melalui callback BLE characteristic.

Ketika user mengirim data melalui BLE write characteristic, callback akan:

1. Mengambil ciphertext hardcoded dari firmware.
2. Melakukan dekripsi menggunakan PSA Crypto.
3. Membandingkan hasil dekripsi dengan input BLE.

Flag asli berada di dalam plaintext hasil dekripsi.

---

# 2. File Challenge

File utama:

```
harald-blatann.hex
```

Identifikasi awal:

```bash
file harald-blatann.hex
```

Output:

```
harald-blatann.hex: Intel hexadecimal object
```

---

# 3. Parsing Firmware

Firmware Intel HEX berisi beberapa range address:

```
0x01000000 - 0x01026a58

0x01026a60 - 0x01028b6c
```

Start address:

```
0x01013065
```

Firmware menggunakan ARM Thumb sehingga perlu dikonversi sebelum analisis disassembly.

---

# 4. Analisis Awal

## String Extraction

Hasil:

```bash
strings harald-blatann.hex
```

memberikan beberapa petunjuk:

```
NNS flag checker

Flag checker

NNS

1337

*** Booting nRF Connect SDK v3.4.0-99553055607b ***

*** Using Zephyr OS v4.4.0-bf801e4e3d19 ***

NNS{th15_is_n0t_th3_fl4g}
```

String:

```
NNS{th15_is_n0t_th3_fl4g}
```

bukan flag sebenarnya.

String tersebut hanya merupakan nilai default salah satu BLE characteristic.

---

# 5. Analisis Static

Karena firmware merupakan ARM Thumb binary, Intel HEX dikonversi terlebih dahulu menjadi binary.

Kemudian dibuat wrapper object ARM:

```bash
cat > wrap.s <<'EOF'
.syntax unified
.thumb

.section .text,"ax",%progbits

.global _start

_start:
.incbin "range0_01000000_01026a58.bin"

EOF
```

Compile:

```bash
clang \
-target thumbv7em-none-eabi \
-c wrap.s \
-o fw.o
```

Disassembly:

```bash
llvm-objdump \
-D \
--adjust-vma=0x01000000 \
--triple=thumbv7em-none-eabi \
fw.o \
> fw.dis
```

---

# 6. Analisis BLE GATT

Ditemukan custom BLE service:

```
12345678-1234-5678-1234-56789abcdef0
```

Characteristic menggunakan UUID turunan:

```
...def1

...def2

...def3

...def4
```

Attribute table penting berada sekitar:

```
0x01026dcc
```

Salah satu characteristic write callback mengarah ke:

```
0x01011b15
```

---

# 7. Analisis Callback Write

Fungsi callback:

```
0x01011b14
```

memiliki alur:

```
Input BLE write
        |
        v
Import AES key
        |
        v
Decrypt ciphertext firmware
        |
        v
Bandingkan plaintext dengan input
        |
        v
Correct / Wrong
```

---

# 8. PSA Crypto Decryption

Callback menggunakan:

```c
psa_cipher_decrypt()
```

dengan parameter:

```
key_id

algorithm = 0x04400040

ciphertext address = 0x01028103

ciphertext length = 0x60
```

Potongan:

```
psa_cipher_decrypt(
    key_id,
    0x04400040,
    0x01028103,
    0x60,
    out,
    0x60,
    &out_len
)
```

---

# 9. Alamat Penting Firmware

Data yang digunakan:

| Data | Address | Size |
|-|-|-|
| Ciphertext | `0x01028103` | `0x60` byte |
| AES Key | `0x01028163` | `0x20` byte |

Key di-import sebelumnya melalui fungsi sekitar:

```
0x01011b80
```

dengan panjang:

```
0x20 byte
```

Sehingga algoritma yang digunakan adalah:

```
AES-256
```

---

# 10. Algoritma Validasi

Proses validasi:

```
1. Ambil ciphertext 0x60 byte dari firmware.

2. Ambil AES key 0x20 byte.

3. Gunakan 16 byte pertama ciphertext sebagai IV.

4. Dekripsi menggunakan AES-256-CBC.

5. Ambil plaintext hasil decrypt.

6. Bandingkan dengan input BLE.
```

---

# 11. Dekripsi AES

Struktur blob:

```
+----------------+
| IV 16 byte     |
+----------------+
| Ciphertext     |
| AES-CBC data   |
+----------------+
```

Parameter:

```
Algorithm:
AES-256-CBC

Key:
32 byte

IV:
16 byte pertama blob
```

---

# 12. Hasil Plaintext

Hasil decrypt:

```
NNS{w1r3lessly_s3nt_4nd_ch3ck3d_by_th3_p0w3r_0f_k1ng_bl4t4nn}\x00...
```

Flag memiliki panjang:

```
61 byte
```

Sehingga memenuhi kondisi:

```
length > 0x3c
```

---

# 13. Penyusunan Solver

Solver:

```
solve_harald_blatann.py
```

melakukan:

1. Membaca Intel HEX.
2. Menggabungkan memory range firmware.
3. Mengambil ciphertext berdasarkan alamat:

```
0x01028103
```

4. Mengambil key AES:

```
0x01028163
```

5. Melakukan AES-256-CBC decrypt.
6. Mengambil string dengan format:

```
NNS{...}
```

---

# 14. Solve Script

Struktur solver:

```python
#!/usr/bin/env python3

from Crypto.Cipher import AES


ciphertext = firmware[
    0x01028103
]

key = firmware[
    0x01028163
]


iv = ciphertext[:16]

data = ciphertext[16:]


cipher = AES.new(
    key,
    AES.MODE_CBC,
    iv
)


plaintext = cipher.decrypt(data)


flag = plaintext.split(
    b"\x00"
)[0]


print(flag.decode())
```

---

# 15. Cara Menjalankan

Jalankan:

```bash
python3 solve_harald_blatann.py
```

Output:

```text
NNS{w1r3lessly_s3nt_4nd_ch3ck3d_by_th3_p0w3r_0f_k1ng_bl4t4nn}

<FLAG>NNS{w1r3lessly_s3nt_4nd_ch3ck3d_by_th3_p0w3r_0f_k1ng_bl4t4nn}</FLAG>
```

---

Flag:

```
NNS{w1r3lessly_s3nt_4nd_ch3ck3d_by_th3_p0w3r_0f_k1ng_bl4t4nn}
```

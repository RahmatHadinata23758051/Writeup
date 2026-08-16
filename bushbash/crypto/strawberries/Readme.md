# Strawberries

## Informasi Challenge

| Field | Value |
|-------|-------|
| **Kategori** | Pwn / Crypto |
| **Judul** | Strawberries |
| **Service** | `nc 34.40.133.67 6001` |

---

# Ringkasan

Challenge menggunakan **AES-CBC** untuk mengenkripsi request client. Server menerima ciphertext, mendekripsinya, kemudian memeriksa beberapa field seperti **Transaction ID**, **Strawberry Count**, **User ID**, dan **Integrity Check**.

Karena mode yang digunakan adalah **CBC**, plaintext pada suatu block dapat dimodifikasi dengan mengubah ciphertext block sebelumnya tanpa mengetahui key AES.

Exploit memanfaatkan **CBC bit-flipping attack** untuk mengubah **User ID** menjadi **PREMIUM_USER**, sehingga pembatasan jumlah strawberry dapat dilewati. Nilai strawberry yang sudah ada pada plaintext ternyata jauh melebihi batas yang dibutuhkan untuk memicu fungsi `displayFlag()`, sehingga flag berhasil dicetak.

---

# File Challenge

File yang diberikan:

```
message.ct

strawberryserver.py
```

File yang **tidak** diberikan:

```
key

iv

flag.txt
```

---

# Analisis Source

Server menggunakan AES dengan mode CBC.

```python
AES.MODE_CBC
```

Setelah ciphertext didekripsi, plaintext diparsing menjadi beberapa field.

| Offset | Data |
|---------|------|
| 0 – 7 | Transaction ID |
| 8 – 15 | Strawberry Count |
| 16 – 31 | User ID |
| 32 – 63 | Integrity Check |

Parsing dilakukan sebagai berikut.

```python
t = request[0:8]

n = request[8:16]

u = request[16:32]

i = request[32:]
```

---

# Target Exploit

Server membatasi jumlah strawberry untuk user biasa.

```python
if u != PREMIUM_USER and n > 5:
    exit()
```

Sedangkan flag hanya diberikan apabila:

```python
if strawberry_count > (1 << 32):
    displayFlag()
```

Dengan demikian exploit harus membuat:

```
User ID
↓

PREMIUM_USER
```

agar request dengan jumlah strawberry yang sangat besar diterima.

---

# Kerentanan

Mode CBC memiliki hubungan:

```
P1 = Dec(C1) XOR IV

P2 = Dec(C2) XOR C1

P3 = Dec(C3) XOR C2
```

Karena plaintext block merupakan hasil XOR dengan ciphertext block sebelumnya, maka perubahan pada ciphertext dapat mengubah plaintext setelah dekripsi.

Secara umum:

```
P2_new =
Dec(C2)
XOR
C1_new
```

Tanpa mengetahui AES key, kita dapat menghitung ciphertext baru menggunakan:

```
C1_new =
C1_old
XOR
P2_old
XOR
P2_target
```

Inilah prinsip **CBC bit-flipping attack**.

---

# Memodifikasi User ID

User ID asli:

```text
00 00 00 00 03 45 f8 d3
81 aa 95 e4 ef 70 27 9a
```

Target User ID:

```text
00 00 00 00 02 34 f9 23
64 3a 95 20 ef 76 27 77
```

Perubahan dilakukan menggunakan rumus:

```
C1_new =
C1_old
XOR
P2_old
XOR
P2_target
```

Karena User ID berada pada block kedua, cukup memodifikasi ciphertext block pertama.

---

# Generator Ciphertext

Ciphertext dimodifikasi sebagai berikut.

```python
ct = bytearray(
    open("message.ct","rb").read()
)

old = bytes.fromhex(
    "000000000345f8d381aa95e4ef70279a"
)

new = bytes.fromhex(
    "000000000234f923643a9520ef762777"
)

for i in range(16):
    ct[i] ^= old[i] ^ new[i]

open("exploit.ct","wb").write(ct)
```

File baru:

```
exploit.ct
```

mengandung ciphertext yang telah dimodifikasi.

---

# Trigger Flag

Ciphertext hasil modifikasi menghasilkan plaintext:

```
requested strawberries:

5007466210972788421
```

dan User ID:

```text
00 00 00 00
02 34 f9 23
64 3a 95 20
ef 76 27 77
```

yang sama dengan:

```
PREMIUM_USER
```

Karena pengecekan premium berhasil dilewati, server menerima jumlah strawberry yang sangat besar.

Output:

```text
Here's your yummy strawberries:

🍓🍓🍓🍓

You now have

5007466210972788421

strawberries

How DARE you >:(
```

Nilai tersebut lebih besar dari:

```
2^32
```

sehingga fungsi:

```python
displayFlag()
```

dipanggil.

---

# Flush Output Issue

Walaupun `displayFlag()` dipanggil, flag tidak langsung muncul.

Penyebabnya adalah server menggunakan:

```python
print(flagtxt.read())
```

tanpa:

```python
flush=True
```

Sementara service masih berada di dalam:

```python
while True:
```

Akibatnya output flag masih berada pada buffer stdout.

Untuk memaksa buffer dikirim ke client, cukup mengirim satu request tambahan.

---

# Final Exploit

```python
from pwn import *

HOST = "34.40.133.67"
PORT = 6001

io = remote(HOST, PORT)

# Trigger displayFlag()
io.send(open("exploit.ct","rb").read())

# Memaksa stdout ter-flush
io.send(open("message.ct","rb").read())

print(io.recvall(timeout=5).decode())
```

---

# Alur Eksploit

```text
Ciphertext Asli
        │
        ▼
CBC Bit-Flipping
        │
        ▼
User ID berubah menjadi
PREMIUM_USER
        │
        ▼
Bypass pengecekan
jumlah strawberry
        │
        ▼
displayFlag() dipanggil
        │
        ▼
Flag masih berada
di stdout buffer
        │
        ▼
Kirim request kedua
        │
        ▼
Buffer ter-flush
        │
        ▼
Flag diterima
```

---

# Flag

```text
bushbash{don't-b@sh-the-str4wberry-bUsh}
```

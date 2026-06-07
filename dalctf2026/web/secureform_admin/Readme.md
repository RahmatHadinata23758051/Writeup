# SecureForm Admin - Writeup

## Ringkasan
Challenge ini kelihatan sederhana di awal: ada form login dengan PIN 4 digit. Setelah masuk ke dashboard, ternyata titik lemah utamanya ada di fitur sorting daftar entry. `orderby` terlihat dibatasi, tapi `order` masih dipakai mentah di query SQL dan bisa dijadikan oracle blind SQLi.

Flag yang didapat:

`dalctf{bl1nd_sqli_0rd3r_by}`

## Langkah yang saya lakukan

### 1. Enumerasi login
Halaman awal cuma menampilkan form PIN 4 digit. Tidak ada petunjuk tambahan di HTML atau CSS, jadi saya uji respons login langsung dari server.

Respons untuk PIN salah selalu konsisten, jadi brute force 0000-9999 adalah jalan paling cepat. Dari sana ketemu PIN yang benar:

- `7392`

### 2. Masuk ke dashboard
Setelah login, aplikasi pindah ke `dashboard.php`. Di sana ada:

- form `add_entry`
- tombol `clear_all`
- opsi sorting lewat parameter query `orderby` dan `order`

Saya tambahkan dua entry dengan `name` yang sama supaya efek sorting bisa diamati dengan jelas.

### 3. Temukan celah di `order`
`orderby` memang terlihat dibatasi, tapi `order` ternyata disisipkan langsung ke query `ORDER BY`.

Payload sederhana ini sudah cukup buat membuktikan ada injeksi:

```text
order=ASC, CASE WHEN 1=1 THEN id ELSE -id END
```

Karena dua entry punya `name` yang sama, hasil sort bisa dipakai sebagai boolean oracle:

- kalau kondisi `true`, urutan jadi `id ASC`
- kalau kondisi `false`, urutan jadi `id DESC`

Dengan cara ini, saya bisa cek ekspresi SQL apa pun secara blind.

### 4. Identifikasi database
Pakai oracle tadi untuk baca metadata. Hasilnya:

- database: `ctf_challenge`
- tabel: `entries,secrets`

Lalu saya dump struktur tabel `secrets`:

- kolom: `id,flag`
- jumlah row: `1`

### 5. Ambil flag
Karena sudah tahu nama tabel dan kolomnya, saya baca isi row pertama dari `secrets.flag` lewat blind extraction:

```sql
SELECT flag FROM secrets LIMIT 1
```

Hasil akhirnya adalah:

`dalctf{bl1nd_sqli_0rd3r_by}`

## Inti bug

Masalah utamanya ada di sanitasi sorting. Developer mencoba membatasi parameter sorting, tapi `order` masih bisa membawa ekspresi SQL tambahan. Karena sorting dipakai pada query `ORDER BY`, saya bisa bikin oracle blind SQLi tanpa perlu error message eksplisit atau UNION.

Kalau diringkas:

- PIN 4 digit bisa dibobol brute force
- dashboard punya blind SQLi di sorting
- flag ada di tabel `secrets`


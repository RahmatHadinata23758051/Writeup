# Writeup JerseyCTF - Tarpit (PWN)

## Informasi Challenge
- Judul: `Tarpit`
- Kategori: `pwn`
- Endpoint: `nc tarpit.aws.jerseyctf.com 9001`

Deskripsi challenge bilang ada service Python untuk ekstrak tar, dan ada jalur submit RSA public key untuk login admin.

---

## Recon awal
Saat connect ke service:

- Muncul banner:
  - `Python 3.12.8`
  - `Ready to read in file`

Service terlihat seperti baca stream tar, tapi setelah ngirim tar valid, baru muncul prompt berikut:

`If you are a developer trying to access data, press q and provide your RSA public key to login, otherwise press any other key and pipe in a tar file`

Ini berarti alurnya:
1. kirim tar file dulu
2. lalu pilih mode developer (`q`) untuk autentikasi key

---

## Mapping alur auth
Setelah pilih `q`, service minta input:

- `RSA KEY:`

Output berikutnya yang teramati:
- `RECEIVED`
- `OPENED`
- `file `
- kalau key random: `Access Denied`
- kalau key kosong: `EXECUTING`

Temuan penting: **input key kosong mem-bypass auth** dan masuk ke mode eksekusi command.

---

## Bukti RCE
Sesudah muncul `EXECUTING`, koneksi jadi seperti shell command executor.

Command yang berhasil dijalankan:
- `id`
- `whoami`
- `pwd`
- `ls`
- `cat flag*`

Hasil penting:
- `uid=0(root)`
- working dir `/chal`
- ada file `flag.txt`

Ambil flag dengan:

```bash
cat /chal/flag.txt
```

---

## Flag

`JCTF{Pl4cing_f1les_can_b3_just_4s_d4ng3rous_as_runn1ng_th3m}`

---

## Script exploit
Saya buat script otomatis di file:

- `exploit.py`

Fungsi script:
1. connect ke host:port
2. kirim tar minimal valid
3. pilih `q`
4. kirim RSA key kosong untuk bypass
5. jalankan `cat /chal/flag.txt`
6. print flag

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python exploit.py
```

---

## Catatan akar masalah (root cause)
Challenge ini kemungkinan punya bug auth logic di jalur developer login:

- kondisi pembanding key/public key salah
- atau validasi kosong (`empty input`) tidak ditolak
- lalu masuk branch `EXECUTING` yang mengeksekusi command di server

Intinya: **autentikasi bisa dibypass dengan input kosong, lalu langsung dapat RCE.**

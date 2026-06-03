# No Cap Just Root (part 3/8)

Part ini melanjutkan foothold dari part sebelumnya. Kunci SSH milik attacker yang sudah didapat di part 2 ternyata masih berlaku, tapi service SSH dibungkus gate aneh di port challenge.

## Ringkasan singkat

Alur solve:

1. Identifikasi bahwa port `46809` sebenarnya adalah SSH yang dibungkus filter
2. Bypass gate dengan banner client SSH yang mengandung komentar `HTTP/1.0`
3. Login sebagai `p4t4t0rz` memakai private key yang ditinggalkan attacker
4. Temukan binary SUID root `skibidi_shell`
5. Eksploit buffer overflow di menu `Cook Exploit`
6. Gunakan ROP chain untuk `open("/root/flag.txt")`, `read()`, lalu `write()`

Flag:

`THC{S0m3_R0P_Ch41n_M4g1c}`

## Recon awal

Service yang diberikan:

```sh
nc 20.40.135.232 46809
```

Kalau diakses mentah, service cuma menjawab:

```text
Not allowed at this time
```

Awalnya ini kelihatan seperti service custom biasa, tapi setelah diproblemkan sedikit lebih jauh, ada perilaku aneh:

- request tertentu memunculkan banner `SSH-2.0-OpenSSH_10.2`
- `nmap -sV -p 46809` juga mengenali servicenya sebagai SSH

Jadi kesimpulan awalnya: port ini adalah SSH yang ditaruh di belakang wrapper/filter.

## Bypass gate SSH

Kunci pentingnya ada di banner client SSH. Wrapper ternyata membolehkan koneksi lanjut kalau banner client mengandung pola yang cocok dengan `HTTP/1.0`.

Supaya koneksi bisa masuk ke SSH asli, client harus mengirim banner seperti ini:

```text
SSH-2.0-OpenSSH_9.6 HTTP/1.0
```

Saya tidak pakai binary `ssh` biasa karena di environment ini tidak ada opsi mudah untuk mengganti banner. Saya pakai `paramiko` dan set:

```python
transport.local_version = "SSH-2.0-OpenSSH_9.6 HTTP/1.0"
```

Dengan itu wrapper lewat, lalu autentikasi SSH normal bisa jalan.

## Initial access

Dari part sebelumnya saya sudah punya private key attacker. User yang valid ternyata:

```text
p4t4t0rz
```

Setelah login berhasil, enumerasi cepat menunjukkan:

```text
uid=1000(p4t4t0rz) gid=1000(p4t4t0rz)
```

Dan di home directory ada binary yang sangat mencurigakan:

```text
/home/p4t4t0rz/skibidi_shell
```

Permission-nya:

```text
-rwsr-x--- 1 root p4t4t0rz ...
```

Ini langsung jadi target utama karena:

- owner `root`
- bit SUID aktif
- group `p4t4t0rz`, jadi user kita boleh execute

## Analisis binary

`checksec`:

```text
Arch: amd64
RELRO: Full RELRO
Canary: No
NX: Enabled
PIE: No
Stripped: No
```

Karena binary tidak strip, analisis jauh lebih cepat. Fungsi menarik:

- `cook_exploit`
- `summon_rizzler`
- `vibe_check`
- helper gadget seperti `useful_gadgets`, `syscall_gadget`, `move_rax_rdi`

Bug utamanya ada di `cook_exploit`.

Potongan logika penting:

```c
char attacker_ip[0x50];
read(0, attacker_ip, 0x1940);
```

Jadi ada overflow besar ke stack. Offset ke RIP adalah `0x58`.

Catatan penting: fungsi ini sebelumnya memakai `scanf`, lalu baru `read`. Karena itu exploit lebih stabil jika input dikirim interaktif per tahap, bukan dari file redirection sekali jalan.

## Strategi exploit

Karena:

- binary non-PIE
- gadget sudah tersedia
- path `/root/flag.txt` ada di section `.data`

saya pilih ROP sederhana berbasis fungsi impor PLT:

1. `open("/root/flag.txt", 0, 0)`
2. pindahkan nilai return fd dari `rax` ke `rdi`
3. `read(fd, .bss, 0x80)`
4. `write(1, .bss, 0x80)`

Alamat penting:

- string `/root/flag.txt`: `0x404008`
- `.bss`: `0x404020`
- `pop rdi; ret`: `0x4012f1`
- `pop rsi; ret`: `0x4012f3`
- `pop rdx; ret`: `0x4012f5`
- `mov rdi, rax; ret`: `0x40130a`
- `open@plt`: `0x401180`
- `read@plt`: `0x4010b0`
- `write@plt`: `0x401080`

## Menjalankan exploit

Flow interaksi dengan binary:

1. pilih menu `1`
2. tunggu prompt `Attacker IP`
3. kirim payload overflow mentah
4. tunggu prompt `Payload name`
5. kirim string pendek biasa agar fungsi lanjut sampai `ret`

Saat fungsi `cook_exploit()` selesai, RIP sudah mengambil ROP chain dan binary menulis isi flag ke stdout.

## File yang saya buat

- `exploit.py` untuk solve otomatis
- `ssh_http10_proxy.py` untuk eksperimen bypass awal wrapper SSH

Proxy itu akhirnya tidak dipakai untuk solve final, karena pendekatan `paramiko` dengan custom banner lebih bersih.

## Cara pakai exploit

Aktifkan virtualenv:

```sh
source /home/nata/ctf_env/bin/activate
```

Lalu jalankan:

```sh
python exploit.py
```

Script akan:

1. retry koneksi sampai gate SSH terbuka
2. login pakai key attacker
3. jalankan binary SUID
4. kirim ROP payload
5. print flag

## Catatan akhir

Part ini bukan pwn jaringan murni dari service `nc`, tapi gabungan:

- SSH gate bypass
- reuse credential dari part sebelumnya
- local privilege escalation lewat binary SUID yang vulnerable

Begitu akses SSH didapat, exploitasinya sendiri cukup straight-forward karena binary memang sengaja menyediakan semua yang dibutuhkan untuk ROP yang bersih.

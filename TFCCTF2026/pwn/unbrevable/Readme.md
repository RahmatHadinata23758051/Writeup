# UNBREVABLE

## Ringkasan

`main()` mencetak alamat `setvbuf`, lalu menerima dua angka dan memakainya langsung sebagai argumen `fgets`. Angka pertama menjadi alamat tujuan dan angka kedua menjadi ukuran baca. Primitive ini dipakai untuk menimpa struktur internal glibc `fork_handlers`, menjalankan callback `setcontext`, lalu membaca flag dengan ORW syscall.

## Proteksi Binary

Hasil recon:

```text
ELF 64-bit LSB x86-64, PIE, dynamically linked
Full RELRO
Canary found
NX enabled
PIE enabled
SHSTK enabled
IBT enabled
```

Binary memakai loader dan libc yang disediakan di direktori challenge: `ld-2.35.so` dan glibc 2.35. Binary tidak stripped.

## Analisis Program

Alur `main` yang relevan:

```c
printf("%p\n", setvbuf);
scanf("%zu %zu", &destination, &size);
fgets((char *)destination, (unsigned int)size, stdin);
fork();
```

Nilai `size` dipotong menjadi 32 bit saat masuk ke `fgets`, tetapi tetap cukup besar untuk payload. Tidak ada validasi alamat maupun ukuran.

Seccomp aktif setelah leak dan hanya mengizinkan `open`, `openat`, `read`, `write`, `rt_sigprocmask`, `rt_sigreturn`, `exit`, `exit_group`, dan `execveat`. Karena `fork()` sendiri akhirnya memakai `clone`, pemrosesan `fork_handlers` sebelum syscall clone menjadi jalur kontrol yang berguna.

## Vulnerability dan Primitive

Primitive yang terbukti:

```text
fgets((char *)angka_pertama, (unsigned int)angka_kedua, stdin)
```

Artinya terdapat arbitrary write dengan panjang terkontrol. Leak pertama memberi libc base:

```text
libc_base = leaked_setvbuf - 0x815f0
```

Global `fork_handlers` berada pada offset `0x221ae0` dari libc base. Format array-nya memiliki count pada `+0x0`, capacity pada `+0x8`, dan pointer array pada `+0x10`. Record callback pertama berada di inline array pada `+0x18`.

Untuk fase prepare, glibc mengurangi count lebih dulu sebelum menghitung record, tetapi callback menerima count asli di `rdi`. Dengan memilih:

```text
count = alamat frame ucontext
array = record - ((count - 1) * 0x20) mod 2^64
```

glbic tetap mengambil record valid di `fork_handlers+0x18`, sementara callback menerima alamat frame sebagai argumen pertama. Callback tersebut diisi dengan `setcontext`.

## Strategi Exploit

Payload menulis langsung ke `fork_handlers` dan tetap berada dalam area writable libc yang sama:

```text
fork_handlers       +0x000  count = frame
fork_handlers       +0x008  capacity = 0x30
fork_handlers       +0x010  array pointer hasil perhitungan modulo
fork_handlers       +0x018  prepare = setcontext
fork_handlers       +0x100  fake ucontext
fork_handlers       +0x400  ROP chain
fork_handlers       +0x540  nama file
fork_handlers       +0x560  buffer output
```

Frame `setcontext` mengatur `rsp` ke ROP chain dan `r10` ke gadget `pop rax; ret`. ROP chain menjalankan:

```text
open(path, O_RDONLY, 0)
read(fd, output, 0x100)
write(1, output, 0x100)
exit(0)
```

Descriptor lokal adalah 3. Pada wrapper remote `socat/ncat`, descriptor flag teruji berada pada fd 6, sehingga script memakai fd 3 lokal dan fd 6 remote.

## Exploit Final

File exploit: [solve.py](/home/nata/ctf/TFCCTF2026/pwn/unbrevable/solve.py)

Jalankan lokal:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Mode GDB:

```bash
python3 solve.py GDB
```

Jalankan remote:

```bash
python3 solve.py REMOTE
```

Hostname remote terbaru sudah menjadi default di script. Host dan port juga bisa diganti dengan `HOST=... PORT=1337`.

Mode lokal membaca `Dockerfile` karena file `flag` hanya tersedia di container challenge. Exploit lokal sudah diuji berulang kali dan menghasilkan isi `Dockerfile`; exploit remote berhasil membaca flag dari service.

## Hasil

Output remote yang diperoleh langsung dari service:

```text
TFCCTF{well_known_technique_brudda}
```

## Catatan Stabilitas

Alamat tidak di-hardcode: libc base dihitung dari leak `setvbuf`, lalu semua alamat target dan gadget dihitung relatif terhadap base tersebut. Payload tidak menimpa `stdin` atau global libc lain di luar area `fork_handlers`, sehingga tidak bergantung pada layout stack maupun brute force ASLR.

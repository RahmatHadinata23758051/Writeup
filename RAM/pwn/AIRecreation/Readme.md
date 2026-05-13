# AI Recreation

Kategori: `pwn`

Target:
- `10.42.5.10:1337`
- `10.42.5.10:22`

Flag:
- `RMCTF{71m3_70_r3l4x}`

## Ringkasan

Challenge ini kelihatannya sederhana karena cuma aplikasi betting berbasis menu, tapi di balik itu ada kombinasi bug yang enak sekali buat dieksploitasi:

- ada `use-after-free` pada pointer note yang tidak dibersihkan setelah `free`
- ada `heap overflow` karena input note ditulis lebih panjang dari ukuran objek
- ukuran chunk `user` dan `note` masuk kelas tcache yang sama, jadi tcache poisoning jadi praktis
- ada callback function pointer di objek `user`
- ada fungsi `WIPFeedback()` yang bisa dipakai untuk menimpa `saved rbp` dan memaksa stack pivot

Jalur exploit akhirnya seperti ini:

1. leak heap dengan UAF
2. lakukan tcache poisoning
3. bentuk fake chunk di sekitar objek `user`
4. ubah pointer note supaya bisa baca/tulis alamat arbitrer
5. leak PIE dari callback pointer
6. leak libc dari `puts@got`
7. ubah callback ke `WIPFeedback`
8. pivot stack ke heap
9. panggil `mprotect` lewat ROP
10. lompat ke shellcode di heap
11. shellcode melakukan `openat + getdents64` untuk cari nama file flag
12. shellcode kedua membaca file flag dan menulis isinya ke stdout

## Recon

Binary utama adalah `challenge`.

Proteksi pentingnya:
- PIE aktif
- NX aktif
- Full RELRO aktif
- tidak ada stack canary

Di `main`, program juga memasang seccomp. Yang penting di sini adalah filter itu bukan whitelist, tapi blacklist. Jadi beberapa syscall diblok, misalnya `open` syscall nomor 2 dan `rt_sigreturn`, tapi `openat` masih bisa dipakai. Ini penting karena arah exploit jadi lebih masuk akal ke `openat`, bukan `open`.

Port `22` hanya memberi petunjuk environment:
- `SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u2`

Dari sini bisa ditebak target pakai Debian 13. Itu berguna untuk mencocokkan libc remote yang benar.

## Analisis Bug

### 1. UAF pada note

Di `user::accessNote()`, saat note dihapus, program memanggil `free(ptr)` dan mengurangi counter note. Masalahnya, pointer note lama di array user tidak di-null-kan. Jadi slot yang sudah di-free masih bisa diakses lagi.

Efeknya:
- kita bisa baca metadata tcache dari chunk yang sudah bebas
- kita bisa tulis ke chunk freed untuk tcache poisoning

### 2. Heap overflow pada isi note

Objek `note` ukurannya `0xb4`, tapi input ke note memakai format yang efektif bisa menulis hingga `256` byte. Jadi isi note bisa meluber ke data setelahnya.

Bug ini bukan jalan utama untuk leak awal, tapi berguna untuk menata ulang isi objek fake note saat overlap sudah berhasil.

### 3. Ukuran chunk note dan user cocok

Ini bagian yang bikin exploit jadi stabil.

- `new user` mengalokasikan objek ukuran `0xb8`
- `new note` mengalokasikan objek ukuran `0xb4`

Setelah dibulatkan allocator, dua-duanya masuk bin yang sama. Artinya chunk note yang bebas bisa dipaksa dialokasikan ulang sebagai area yang menimpa objek `user`.

### 4. Callback pointer di objek user

Di `user + 0x80` ada function pointer callback. Normalnya pointer ini menunjuk ke fungsi print username. Kalau alamat ini bisa kita overwrite, kita dapat kontrol alur eksekusi saat menu utama menampilkan user aktif.

### 5. Stack pivot lewat WIPFeedback

Fungsi `WIPFeedback()` membaca `0x48` byte ke buffer stack ukuran `0x40`. RIP tidak langsung tertimpa, tapi `saved rbp` bisa diganti. Itu cukup, karena saat `main` keluar, epilog-nya memakai `rbp` untuk membentuk stack:

```c
lea rsp, [rbp-0x10]
pop rbx
pop r12
pop rbp
ret
```

Jadi begitu `rbp` diarahkan ke fake frame di heap, kontrol flow bisa dipindah ke ROP chain yang kita siapkan.

## Membangun Primitive

### Leak heap

Urutan heap yang dipakai:

1. buat user
2. buat beberapa note
3. free note 2 lalu note 1
4. akses lagi stale pointer note 1

Karena chunk freed sudah masuk tcache, isi awal chunk sekarang berisi pointer encoded safe-linking. Dari leak ini bisa dipulihkan posisi dua chunk note yang bersebelahan, lalu dari sana dihitung alamat objek `user`.

### Tcache poisoning

Setelah alamat note pertama diketahui, field `fd` di chunk freed ditulis ulang dengan pointer encoded yang mengarah ke area `user - 0x40`. Ketika allocator dipanggil dua kali:

- alokasi pertama mengambil chunk note biasa
- alokasi kedua mengembalikan pointer ke area buatan kita di dekat `user`

Di titik ini kita punya fake chunk yang overlap dengan objek `user`.

### Arbitrary read/write

Dengan overlap itu, isi pointer array note di dalam `user` bisa disusun ulang. Trik yang dipakai:

- note 1 diarahkan ke alamat target yang ingin dibaca atau ditulis
- note 3 diarahkan balik ke fake chunk supaya primitive ini bisa dipakai berulang

Karena operasi `show note` memakai `puts(ptr)` dan `edit note` menulis ke pointer tersebut, kita dapat primitive baca/tulis alamat arbitrer dalam batas yang cukup untuk exploit.

## Leak PIE dan libc

PIE dileak dari callback pointer di `user + 0x80`.

Setelah base PIE diketahui, `puts@got` bisa dihitung. Dari `puts@got`, alamat `puts` di libc remote ikut bocor.

Pada tahap ini sempat ada jebakan penting:

- libc lokal saya bukan libc remote
- kalau offset libc diambil dari mesin lokal, base yang didapat akan salah

Karena banner SSH menunjukkan Debian 13, saya ambil paket `libc6_2.41-12+deb13u2_amd64.deb`, ekstrak `libc.so.6`, lalu pakai itu untuk menghitung offset `puts`, `mprotect`, dan gadget ROP.

## Kenapa Tidak Pakai ORW ROP Langsung

Awalnya saya coba ORW murni lewat ROP dan syscall chain, tapi ada dua masalah:

- panjang ROP chain cepat membesar karena harus set register berkali-kali
- semua write note lewat `scanf("%[^\n]")`, jadi byte newline `0x0a` di payload bisa bikin satu attempt langsung gagal

Akhirnya pendekatan yang lebih bersih adalah:

1. pakai ROP pendek untuk `mprotect(heap_page, 0x2000, 7)`
2. lompat ke shellcode di heap

Dengan begitu chain ROP sangat pendek, sementara logika file operation dipindah ke shellcode yang jauh lebih fleksibel.

## Shellcode Final

Saya pakai dua mode shellcode:

### Mode 1: list direktori

Shellcode pertama melakukan:

- `openat(AT_FDCWD, ".", O_DIRECTORY, 0)`
- `getdents64`
- `write(1, buf, len)`

Dari output ini terlihat nama file flag:

`flaguWSz45p3OjxUW3GaTTpV9VoHOREE5godifEBLjFMk.txt`

### Mode 2: baca file flag

Untuk pembacaan file, mode paling stabil adalah:

- `openat(AT_FDCWD, "/flaguWSz45p3OjxUW3GaTTpV9VoHOREE5godifEBLjFMk.txt", O_RDONLY, 0)`
- `mmap(0x13370000, 0x1000, PROT_READ, MAP_PRIVATE, fd, 0)`
- `write(1, mapped, 0x200)`

Pendekatan `read` biasa sempat gagal pada beberapa attempt, tapi `mmap + write` stabil dan langsung mengeluarkan flag.

## Solver

File solver final ada di:

- [solve.py](/home/nata/ctf/RAM/pwn/AIRecreation/solve.py)

Solver default sekarang melakukan semuanya otomatis:

1. connect ke remote
2. exploit sampai dapat arbitrary read/write
3. leak PIE
4. leak libc
5. stack pivot
6. jalankan shellcode listing
7. parse nama file flag dari output `getdents64`
8. jalankan shellcode kedua untuk membaca file flag

Kalau mau menjalankan manual nanti:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py ./challenge
```

Mode debug juga masih saya sisakan lewat environment variable:

- `SC_MODE=marker` untuk cek shellcode sudah tereksekusi
- `SC_MODE=ls` untuk dump isi direktori
- `SC_MODE=mmapfile FLAG_PATH=/path/file` untuk baca file tertentu

## Catatan Penting

- Exploit ini tetap punya unsur retry karena semua write harus lolos dari larangan byte newline.
- Solver sudah menangani itu dengan loop retry.
- File `libc_remote.so.6` disimpan di folder yang sama karena offset libc remote memang berbeda dari libc lokal.

## Penutup

Inti challenge ini bukan sekadar satu bug tunggal, tapi bagaimana beberapa bug kecil saling melengkapi:

- UAF memberi leak heap
- tcache poisoning memberi overlap ke objek `user`
- overlap memberi arbitrary read/write
- callback pointer memberi titik kontrol
- `WIPFeedback` memberi pivot
- ROP singkat membuka jalan ke shellcode

Begitu jalur itu stabil, sisanya tinggal memilih metode baca file yang paling tahan terhadap pembatasan input. Di challenge ini, kombinasi `mprotect + shellcode + mmap` adalah jalur yang paling rapi.

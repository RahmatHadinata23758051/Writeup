# Writeup `cbc_plus_plus_1`

Challenge ini kelihatannya simpel banget di awal. Programnya cuma nyimpen angka ke `std::vector<unsigned long long>`, terus ada menu buat swap dua elemen. Biasanya kalau lihat soal beginian, insting pertama ya cari out-of-bounds. Dan ternyata memang itu sumber masalah utamanya.

Target remote:

```bash
nc pwn.cbd2026.cloud 9999
```

Binary yang dipakai:

- `cbc_plus_plus_1`
- source disediakan: `cbc_plus_plus_1.cpp`

## Recon awal

Pertama saya cek proteksi binary:

```bash
checksec --file=cbc_plus_plus_1
```

Hasil pentingnya:

- `Full RELRO`
- `Canary found`
- `NX enabled`
- `No PIE`
- `SHSTK enabled`
- `IBT enabled`

Jadi dari sini sudah kelihatan kalau jalur ret2libc klasik lewat overwrite return address itu bukan opsi yang enak. Bukan cuma karena canary, tapi juga karena ada shadow stack dan IBT. Artinya saya butuh primitive lain yang tidak bergantung pada hijack control flow via stack.

## Bedah source

Source programnya pendek:

```cpp
case 2:
    std::cout << "Index 1: ";
    std::cin >> ind1;
    std::cout << "Index 2: ";
    std::cin >> ind2;
    num = vec->operator[](ind1);
    vec->operator[](ind1) = vec->operator[](ind2);
    vec->operator[](ind2) = num;
    std::cout << "Done" << std::endl;
    break;
```

Masalahnya ada di `operator[]`. Akses ini tidak ada bounds check. Sementara indeks dibaca sebagai `int`, lalu di asm dikonversi pakai `movsxd`, jadi angka negatif ikut dibawa sebagai signed value, lalu dipakai sebagai offset 64-bit.

Implementasi `vector::operator[]` yang dipanggil binary ini bentuknya pada dasarnya cuma:

```asm
rax = [vec_begin]
rdx = index
rdx <<= 3
rax += rdx
return rax
```

Artinya `vec[-1]`, `vec[-2]`, `vec[-3]`, dan seterusnya benar-benar ngarah ke alamat sebelum buffer vector di heap.

## Layout yang penting

Waktu `init()`, program melakukan:

1. baca nama ke global `std::string name`
2. `new std::vector<unsigned long long>()`
3. `vec->reserve(0x100)`

Dari pengecekan di GDB, object `std::vector` sendiri ada di heap, dan isinya tiga pointer:

- `begin`
- `end`
- `cap`

Setelah `reserve(0x100)`, layout-nya kurang lebih jadi begini:

```text
vec object:
  [0x00] begin -> buffer angka
  [0x08] end   -> awal buffer juga, karena size masih 0
  [0x10] cap   -> begin + 0x800
```

Karena `operator[]` membaca dari `begin`, maka:

- `vec[-3]` mengarah ke `begin`
- `vec[-2]` mengarah ke `end`
- `vec[-1]` mengarah ke `cap`

Ini kunci exploit-nya.

## Primitive yang dipakai

Awalnya saya sempat mikir soal arbitrary read langsung dari OOB swap, tapi swap sendirian cuma tukar dua qword. Itu kuat, tapi belum otomatis nyaman dipakai buat baca string atau pointer libc.

Yang akhirnya dipakai adalah kombinasi:

1. pakai `swap(-3, idx)` untuk menukar `begin`
2. pakai `swap(-2, idx)` untuk menukar `end`
3. manfaatkan `push_back()` sebagai write gadget

Kalau `end` saya arahkan ke target address, lalu `push_back(x)`, maka nilai `x` akan ditulis ke alamat yang sedang ditunjuk `end`.

Secara konsep:

```text
vector.end = target
push_back(value)
=> *(target) = value
```

Supaya vector tidak rusak permanen, setelah write selesai `begin/end/cap` saya restore lagi ke nilai semula dengan swap balik.

Jadi primitive utamanya berubah menjadi:

- `arb write 8-byte`

Setelah punya arbitrary write, saya pakai object `std::string name` sebagai oracle untuk arbitrary read.

## Kenapa `name` bisa dipakai buat leak

Menu selalu mencetak:

```cpp
std::cout << "Hi, " << name << std::endl;
```

Kalau field internal `std::string name` diubah supaya pointer data-nya mengarah ke alamat tertentu, lalu length-nya di-set ke ukuran yang kita mau, setiap kali menu tampil program akan mencetak bytes dari alamat itu.

Untuk string panjang di libstdc++, layout `std::string` global ini cukup sederhana:

- offset `+0x00`: pointer data
- offset `+0x08`: size
- offset `+0x10`: area buffer/capacity tergantung mode

Karena saya kasih nama awal sepanjang 32 byte, objek `name` masuk mode heap string, jadi destructor-nya nanti juga berguna.

Primitive leak yang dipakai:

1. overwrite `name.ptr = alamat_target`
2. overwrite `name.size = panjang`
3. tunggu output `Hi, `
4. baca `panjang` byte setelah itu
5. reset lagi `name` ke string kosong supaya menu berikutnya tidak nge-print data liar terus-menerus

Dengan ini saya bisa leak:

- GOT entry `__libc_start_main`
- pointer `vec`
- isi object vector di heap
- area libc lain yang diperlukan

## Kenapa saya tidak pakai return address

Di challenge ini ada:

- canary
- shadow stack
- IBT

Jadi walaupun secara teori bisa cari jalur stack corruption, effort-nya jadi jauh lebih ribet dan belum tentu worth it. Begitu lihat ada global object C++ dan ada mekanisme exit handler, saya geser fokus ke sana karena jalurnya lebih bersih.

## Target akhir: exit handler, bukan stack

Ada satu detail penting di binary:

global `std::string name` didaftarkan ke `__cxa_atexit`, supaya destructor-nya dipanggil saat program keluar.

Artinya di libc ada entry exit handler yang berisi:

- encoded function pointer ke destructor string
- argumen = alamat object `name`
- `dso_handle`

Kalau entry ini bisa saya ubah menjadi:

- function pointer = `system`
- argumen = pointer ke string command

maka saat user pilih `3. Exit`, program akan mengeksekusi `system(command)` secara natural, tanpa sentuh return address sama sekali.

Itu sangat cocok untuk challenge ini.

## Pointer mangling di `__cxa_atexit`

Masalahnya, pointer function di exit handler tidak disimpan mentah. Glibc melakukan pointer mangling.

Dari leak entry yang asli, saya dapat:

- encoded destructor pointer
- argumen asli (`&name`)
- `dso_handle`

Lalu saya leak juga pointer destructor sebenarnya dari GOT:

```text
real_dtor = GOT[basic_string destructor]
encoded_dtor = entry->func
```

Karena skema mangle glibc untuk pointer ini adalah rotasi + xor dengan guard, guard bisa dipulihkan:

```text
guard = ror(encoded_dtor, 0x11) ^ real_dtor
```

Setelah guard ketemu, saya bisa encode `system` dengan format yang sama:

```text
encoded_system = rol(system ^ guard, 0x11)
```

Lalu overwrite:

- `entry->func = encoded_system`
- `entry->arg = vec_begin`

Kenapa `vec_begin`? Karena saya taruh command di elemen awal vector, jadi alamat buffer vector sudah langsung jadi pointer ke string command.

## Jebakan waktu ngerjain remote

Bagian ini yang paling nyebelin justru bukan primitive-nya, tapi soal libc remote.

Awalnya saya kira cukup:

```text
libc_base = leak(__libc_start_main@got) - offset_local___libc_start_main
system    = libc_base + offset_local_system
```

Ternyata remote memang mirip libc lokal, tapi offset `system` beda `0x10`.

Di lokal:

- `system = 0x58750`

Di remote hasil leak simbol:

- `system = 0x58740`

Efeknya bikin exploit terlihat “hampir benar” tapi command tidak jalan.

Begitu saya leak langsung entry `dynsym[1050]` dari libc remote, kelihatan kalau simbol `system` memang ada di index yang sama, tapi `st_value`-nya beda sedikit. Dari situ alamat `system` yang dipakai exploit saya ambil langsung dari `dynsym` remote, bukan lagi percaya mentah ke offset lokal.

Itu yang bikin payload akhirnya stabil di service.

## Flow exploit final

Urutan exploit finalnya seperti ini:

1. kirim nama panjang 32 byte supaya `name` jadi heap string
2. isi vector dengan beberapa angka awal, termasuk string command yang sudah dipacking ke qword
3. bangun primitive arbitrary write lewat korupsi `begin/end/cap`
4. bangun primitive arbitrary read lewat manipulasi `std::string name`
5. leak `__libc_start_main@got`
6. hitung `libc_base`
7. leak simbol `system` langsung dari `dynsym` remote
8. leak `vec` lalu baca `vec_begin`
9. ambil exit handler entry untuk destructor `name`
10. recover pointer guard dari encoded destructor
11. encode alamat `system`
12. overwrite exit entry:
    - function pointer -> encoded `system`
    - argumen -> `vec_begin`
13. pilih menu `3`
14. program keluar dan menjalankan `system(command)`

Command yang dipakai terakhir:

```text
cat flag.txt
```

## Flag

Flag yang keluar dari remote:

```text
CBC{c47884f6827d5fdb9799e7dad890e04934f47b29ab5e9f20a04bb4d6d9426fcb}
```

## File exploit

Script final ada di:

[exploit.py](/home/nata/ctf/cyberbreaker-qual/pwn/exploit.py)

Jalankan lokal:

```bash
source /home/nata/ctf_env/bin/activate
python exploit.py
```

Jalankan remote:

```bash
source /home/nata/ctf_env/bin/activate
python exploit.py REMOTE
```

## Penutup

Challenge ini enak karena bug-nya kecil, tapi ruang eksploitasinya lebar. Swap out-of-bounds doang ternyata cukup buat berubah jadi arbitrary write, lalu arbitrary read, lalu command execution penuh tanpa harus nyentuh stack sama sekali.

Kalau disederhanakan, inti soal ini ada di tiga hal:

- `vector::operator[]` tanpa bounds check
- object layout C++ yang bisa dimanipulasi
- exit handler libc yang lebih realistis dipakai daripada ret smash

Begitu ketiganya nyambung, sisanya tinggal kerja rapih di detail implementasi.

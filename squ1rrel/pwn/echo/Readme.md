# Writeup pwn/echo

Challenge ini kelihatannya sederhana, tapi ternyata ada kombinasi bug yang enak banget buat dieksploit.

## Info awal
Binary `echo` adalah:
- ELF 32-bit ARM (PIE)
- Full RELRO
- Tidak ada canary
- Stack executable (`GNU_STACK RWE`)

Service jalan via qemu-user:
- `qemu-arm -L /usr/arm-linux-gnueabi ./echo`

## Recon cepat
Fungsi utama (hasil disassembly) intinya begini:

1. `puts("Echo")`
2. `fgets(buf, 0x10, stdin)` ke buffer stack yang sebenarnya cuma 8 byte
3. `printf(buf)` (format string vuln)
4. `read(0, buf, 0x10)` lagi ke buffer yang sama
5. `return`

Jadi ada dua bug sekaligus:
- **Format String** di `printf(buf)`
- **Stack Overflow** karena buffer 8 byte diisi sampai 16 byte

## Tujuan eksploitasi
Karena overflow dari `read` bisa overwrite saved LR, kita bisa kontrol PC saat fungsi return.
Masalahnya kita butuh alamat stack untuk lompat ke shellcode.

Di sini format string dipakai buat leak alamat:
- payload: `%13$p`
- remote selalu leak: `0x3ffffb74`

Dari kalibrasi runtime, alamat buffer stack yang dipakai `read` adalah:

`buf_addr = leak - 0x18c`

## Kenapa tidak langsung shellcode besar?
Overflow dari `read` cuma kasih kita 16 byte total:
- 12 byte bebas
- 4 byte terakhir dipakai jadi return address (PC)

Shellcode `cat flag.txt` jelas lebih panjang dari 12 byte.
Solusinya: pakai **stager 12-byte**.

## Rantai exploit
1. Kirim `%13$p` untuk leak stack pointer.
2. Kirim payload overflow 16 byte:
   - 12 byte Thumb stager: `read(0, sp, 0xfe)`
   - 4 byte return address: `buf_addr + 1` (bit Thumb aktif)
3. Setelah return, eksekusi pindah ke stack (Thumb), stager jalan, lalu baca stage-2 dari socket ke stack.
4. Kirim stage-2 shellcode (Thumb) yang melakukan open/sendfile untuk `flag.txt`.
5. Flag keluar ke stdout koneksi.

## Kenapa Thumb?
Thumb bikin instruksi lebih pendek (2-byte), jadi bisa muat stager fungsional dalam 12 byte.
Kalau pakai ARM mode, ruang 12 byte terlalu mepet buat setup syscall yang layak.

## Script exploit
Exploit final ada di file:
- `solve.py`

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

## Hasil
Flag yang didapat dari service:

`squ1rrel{i_l0v3_n1s@l@_h3_1s_s0_c00l}`

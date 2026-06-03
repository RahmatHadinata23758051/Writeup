# Phantom

## Ringkasan

Challenge ini adalah custom bytecode VM. Bug utamanya ada di instruksi `PEEK` dan `POKE`: nilai register dipakai sebagai index ke stack VM tanpa bounds check. Karena seluruh state VM disimpan di stack frame fungsi interpreter, index yang cukup besar bisa keluar dari area stack VM dan menimpa saved return address.

Setelah return address milik interpreter bisa ditulis, exploit-nya tinggal:

1. Tulis ROP chain tahap pertama ke saved RIP interpreter.
2. Chain pertama memanggil `read(0, .bss, len(stage2))`.
3. Setelah `read`, pivot `rsp` ke `.bss`.
4. ROP tahap kedua menjalankan syscall `open("/home/flag.txt", 0)`, `read(3, buf, 0x100)`, lalu `write(1, buf, 0x100)`.

Flag yang keluar:

`THEM?!CTF{ph4nt0m_byt3c0d3_vm_3sc4p3_m4st3r}`

## Recon

Binary:

- ELF 64-bit
- static
- stripped
- NX enabled
- No PIE
- No canary

Karena static dan non-PIE, alamat gadget ROP tetap. Ini sangat membantu begitu kita dapat arbitrary write ke return address.

Prompt program:

```text
Submit your phantom script as hex-encoded bytecode.
Max code size: 2048 bytes (4096 hex chars)
```

Jadi input pertama adalah satu baris hex, lalu bytecode hasil decode dieksekusi oleh VM.

## Analisis VM

Dari disassembly fungsi interpreter di `0x4019ee`, terlihat layout penting di stack:

- buffer bytecode ada di sekitar `rbp-0xb00`
- register VM ada di sekitar `rbp-0x2f0`
- stack VM ada di sekitar `rbp-0x270`

Ada dispatcher opcode `0x00` sampai `0x17`. Beberapa opcode penting yang dipakai waktu eksploitasi:

- `0x02` = `PUSH imm64`
- `0x03` = `POP reg`
- `0x15` = `POKE reg`
- `0x17` = `INC reg`

Instruksi `POKE` kira-kira bekerja seperti ini:

```c
idx = regs[reg];
value = vm_stack[sp - 1];
vm_stack[idx] = value;
```

Masalahnya, `idx` tidak pernah dicek.

Addressing yang dipakai `POKE` adalah:

```c
[rbp + (idx + 0x112) * 8 - 0xb00]
```

Kalau dihitung:

- `idx = 0` mengarah ke awal stack VM
- `idx = 79` mengarah ke `rbp + 8`, yaitu saved RIP interpreter

Itu artinya kita punya primitive write 8-byte ke return address hanya dengan:

1. isi sebuah register dengan `79`
2. `PUSH` nilai target
3. `POKE` ke register tadi

Saya validasi dulu dengan payload kecil yang menulis `0x4141414141414141` ke index `79`, dan proses langsung crash saat interpreter return. Berarti kontrol RIP benar-benar kena.

## Strategi Eksploitasi

### Tahap 1: tulis ROP awal ke stack return interpreter

Karena kita belum punya tempat yang nyaman untuk chain panjang, saya tulis ROP kecil langsung ke area return interpreter:

```c
read(0, .bss, len(stage2));
pivot rsp = .bss;
```

Gadget yang dipakai:

- `pop rdi ; ret`
- `pop rsi ; ret`
- `pop rdx ; pop rbx ; ret`
- `pop rax ; ret`
- `syscall ; ret`
- `pop rsp ; ret`

Keuntungannya:

- stage pertama pendek
- tidak perlu tahu alamat stack runtime
- stage kedua bisa dikirim raw binary setelah hex bytecode selesai dibaca

### Tahap 2: ROP penuh di `.bss`

Setelah `read`, stack dipindah ke `.bss`, lalu chain kedua jalan:

1. `open("/home/flag.txt", 0)`
2. `read(3, FLAG_BUF, 0x100)`
3. `write(1, FLAG_BUF, 0x100)`
4. `exit(0)`

Saya sengaja pakai fd `3` setelah `open`, karena untuk service model begini stdin/stdout/stderr biasanya `0/1/2`, jadi file pertama yang dibuka program akan jadi `3`. Di remote ini valid.

## Kenapa Bisa Kirim Stage 2 Setelah Hex?

Program hanya membaca satu line hex untuk parser VM. Setelah itu file descriptor `stdin` tetap hidup. Begitu interpreter selesai dan control flow pindah ke ROP tahap pertama, chain tadi memanggil `read(0, .bss, len(stage2))`.

Jadi format kirimnya:

1. `sendline(hex(stage1_vm_bytecode))`
2. `send(stage2_raw_rop)`

Tidak perlu koneksi kedua.

## Exploit Script

Script final ada di:

- `exploit.py`

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 exploit.py
```

Mode lokal juga ada:

```bash
python3 exploit.py LOCAL=1
```

## Potongan Bug yang Paling Penting

Secara konsep, ini bagian yang fatal:

```c
target = regs[user_reg];
vm_stack[target] = popped_value;
```

Tanpa validasi bahwa `target` masih berada dalam batas stack VM.

Begitu nilai register bisa diisi bebas dengan `PUSH imm64` lalu `POP reg`, custom VM ini pada dasarnya memberi arbitrary indexed write ke stack frame interpreter.

## Catatan Akhir

Hal yang bikin challenge ini cepat runtuh:

- state VM diletakkan di stack
- register bisa berisi angka 64-bit bebas
- `PEEK/POKE` tidak membatasi index
- binary non-PIE, jadi ROP address tetap

Begitu satu saja dari poin itu diperbaiki, exploit-nya jauh lebih ribet. Yang paling tepat tentu menambahkan bounds check di `PEEK` dan `POKE`, dan idealnya memisahkan state VM ke heap atau struct yang tidak berdampingan dengan control data fungsi.

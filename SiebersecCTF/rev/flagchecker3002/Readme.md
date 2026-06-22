# Writeup flagchecker3002

Challenge ini adalah sebuah file Python bytecode (`chall.pyc`) yang dikompilasi untuk Python 3.12.

## Analisis Awal
Setelah melakukan disassembly menggunakan module `dis` di Python, ditemukan tiga fungsi utama:
1. `enc(a)`: Fungsi enkripsi awal yang tampak sangat sederhana (hanya XOR dengan key).
2. `main()`: Fungsi utama yang meminta input flag dan memvalidasinya.
3. `_()`: Fungsi yang dipanggil sebelum `main()` dan melakukan manipulasi memory menggunakan `ctypes`.

Jika kita mencoba menghitung flag secara naif dari fungsi `enc` yang terlihat di disassembly awal, kita akan mendapatkan:
`sctf{this_is_not_the_real_flag!!}`.

## Self-Modifying Bytecode
Fungsi `_()` sebenarnya adalah fungsi yang memodifikasi bytecode fungsi `enc` saat runtime. Fungsi ini memiliki beberapa instruksi `JUMP_FORWARD` yang sangat jauh (ke offset 65036) sebagai teknik obfuscation untuk mencegah disassembly sederhana atau eksekusi normal jika tidak ditangani dengan benar.

Setelah mem-patch bytecode fungsi `_()` untuk melewati jump-jump tersebut dan menjalankannya, kita dapat melihat perubahan pada bytecode fungsi `enc` di memory.

## Reversing Logic
Bytecode `enc` yang baru memiliki logika sebagai berikut:
1. Mengambil input `c` dan key `k`.
2. Melakukan operasi `temp = (c + k) % 255`.
3. Melakukan XOR antara `temp` dengan sebuah magic sequence: `b'\x0e\xc0\xe0\xcd\xf7\xe0\x80\xff\xc9\xf1\x08\xff7\xfe\xe1\xc3\xb0\x02\x8f\xc5\xf8\xdc\t\x81\xe7\xc0\xd7\xfc\xf1\x18\xb0\xb2\xff'`.
4. Membandingkan hasilnya dengan `target`.

Persamaan enkripsinya:
`target[i] = ((input[i] + key[i]) % 255 ^ magic[i]) & 255`

Untuk mendapatkan flag:
`input[i] = ((target[i] ^ magic[i]) - key[i]) % 255`

## Solusi
Script `solve.py` melakukan perhitungan kebalikan dari logika enkripsi yang ditemukan di memory.

```python
key = b'\x07<q\xa6\xdb\x10Ez\xaf\xe4\x19N\x83\xb8\xed"W\x8c\xc1\xf6+`\x95\xca\xff4i\x9e\xd3\x08=r\xa7'
target = b't_\x05\xc0\xa0d-\x13\xdc\xbbp=\xdc\xd6\x82V\x08\xf8\xa9\x93t\x12\xf0\xab\x93k\x0f\xf2\xb2o\x1cS\xda'
magic = b'\x0e\xc0\xe0\xcd\xf7\xe0\x80\xff\xc9\xf1\x08\xff7\xfe\xe1\xc3\xb0\x02\x8f\xc5\xf8\xdc\t\x81\xe7\xc0\xd7\xfc\xf1\x18\xb0\xb2\xff'

flag = []
for i in range(len(target)):
    temp = target[i] ^ magic[i]
    c = (temp - key[i]) % 255
    flag.append(c)

print("".join(chr(x) for x in flag))
```

Flag: `sctf{three_thousand_and_twoooooo}`

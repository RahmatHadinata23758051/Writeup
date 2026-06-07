# Writeup: someone said steg?

## Deskripsi Challenge
Challenge ini memberikan sebuah file gambar `chall.png` dengan deskripsi "everyone <3s steg right?". 

## Analisis
1.  **Identifikasi File**: 
    Menggunakan perintah `file` dan `exiftool`, diketahui bahwa `chall.png` adalah sebuah **APNG (Animated PNG)** yang terdiri dari 16 frame.
    
2.  **Pemeriksaan Metadata & Strings**: 
    Tidak ditemukan informasi berguna pada metadata atau hasil perintah `strings`.

3.  **Analisis Steganografi**:
    - Menggunakan `zsteg` untuk memeriksa LSB steganografi.
    - `zsteg` menunjukkan adanya data mencurigakan pada chunk `fdAT` (chunk data frame APNG).
    - Terlihat bahwa setiap frame memiliki satu karakter yang tersembunyi di awal data zlib yang dikompresi.
    
4.  **Ekstraksi Data**:
    Setiap frame dalam APNG disimpan dalam chunk `IDAT` (frame pertama) dan `fdAT` (frame berikutnya). 
    Dengan mendekompresi data zlib dari setiap chunk tersebut, kita dapat melihat data pixel mentah.
    
    Data pixel untuk gambar ini menggunakan format **RGBA** (4 byte per pixel).
    Setelah diperiksa, ditemukan bahwa nilai **Alpha** (byte ke-4) dari pixel pertama (0,0) di setiap frame berisi satu karakter dari flag.

    Frame ke- | Chunk | Nilai Alpha Pixel (0,0) | Karakter
    --- | --- | --- | ---
    0 | IDAT | 100 | d
    1 | fdAT | 97 | a
    2 | fdAT | 108 | l
    3 | fdAT | 99 | c
    4 | fdAT | 116 | t
    5 | fdAT | 102 | f
    6 | fdAT | 123 | {
    7 | fdAT | 112 | p
    8 | fdAT | 105 | i
    9 | fdAT | 97 | a
    10 | fdAT | 110 | n
    11 | fdAT | 111 | o
    12 | fdAT | 109 | m
    13 | fdAT | 97 | a
    14 | fdAT | 110 | n
    15 | fdAT | 125 | }

## Script Solve
Berikut adalah script Python untuk mengekstrak flag secara otomatis:
```python
import struct
import zlib

def solve():
    flag = ""
    with open('chall.png', 'rb') as f:
        f.read(8) # PNG Magic
        while True:
            chunk_header = f.read(8)
            if not chunk_header: break
            length, name = struct.unpack('>I4s', chunk_header)
            data = f.read(length)
            f.read(4) # CRC
            if name == b'IDAT':
                d = zlib.decompress(data)
                flag += chr(d[4]) # Alpha channel pixel (0,0)
            elif name == b'fdAT':
                d = zlib.decompress(data[4:])
                flag += chr(d[4]) # Alpha channel pixel (0,0)
    print(flag)

if __name__ == "__main__":
    solve()
```

## Flag
<FLAG>dalctf{pianoman}</FLAG>

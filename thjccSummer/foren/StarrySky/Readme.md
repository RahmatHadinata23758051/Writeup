# Starry Sky

## Ringkasan

Flag tidak disimpan sebagai nilai byte utuh pada piksel. Payload ada di LSB kanal Blue. Bit yang dipakai tidak berurutan rapat, tetapi dibaca setiap 5 piksel. Setelah 8 bit dikumpulkan, byte hasilnya masih di-XOR dengan satu byte key `0x5a`.

Hasil decode:

```
THJCC{c0unt1ng_blu3s_by_thr33s}
```

## File Challenge

Arsip:

```
challenge.png(2).zip
```

Isi utama:

```
challenge.png
```

Tipe file:

```
PNG image data, 512 x 512, 8-bit/color RGB, non-interlaced
```

## Analisis Awal

Metadata PNG memberi clue:

```
Even the truth wears a mask here -- a single byte lifts it.
The rest is just knowing which grains to read, and how far apart.
```

Maknanya cocok dengan:

- `single byte lifts it` → byte hasil ekstraksi di-XOR dengan key satu byte.
- `which grains to read` → kanal/bit tertentu yang dibaca.
- `how far apart` → bit dibaca dengan stride tertentu.

Tidak ada data tambahan setelah chunk `IEND`, jadi payload bukan append file di akhir PNG.

## Analisis Static

Gambar adalah RGB 512×512. Kanal warna diekstrak menjadi array row-major. Tes byte-level langsung menghasilkan kandidat palsu pendek, jadi pendekatan yang benar adalah membaca bit-plane.

Pencarian dilakukan pada bit-plane RGB dengan known plaintext prefix:

```
THJCC{
```

Untuk setiap kandidat bit-plane, start, stride, dan bit-order, 8 bit dikumpulkan menjadi satu byte. Key dihitung dari byte pertama:

```
key = extracted_byte_0 XOR ord('T')
```

Kandidat valid yang ditemukan:

```
channel    = Blue
bit        = 0 / LSB
start      = 0
bit stride = 5
bit order  = MSB-first
xor key    = 0x5a
```

Kandidat ekuivalen pada data RGB interleaved juga muncul sebagai:

```
start  = 2
stride = 15
```

Itu sama saja dengan membaca kanal Blue setiap 5 pikel karena urutan interleaved adalah `R, G, B`.

## Analisis Dynamic

Tidak ada binary yang perlu dijalankan. Validasi dilakukan dengan ekstraksi bit dari gambar.

Langkah decode:

1. Ambil semua piksel dalam urutan row-major.
2. Ambil LSB kanal Blue dari setiap piksel.
3. Mulai dari indeks bit `0`.
4. Untuk setiap byte, ambil 8 bit dengan jarak `5`:

```
bit_index = current_position + i * 5
```

5. Pack 8 bit secara MSB-first.
6. XOR byte dengan `0x5a`.
7. Ulangi sampai karakter `}`.

## Algoritma Validasi atau Encoding

Rumus decoding:

```
enc_byte = pack_msb(blue_lsb[pos + 0*5], ..., blue_lsb[pos + 7*5])
plain    = enc_byte XOR 0x5a
pos     += 8 * 5
```

Byte plaintext membentuk flag:

```
THJCC{c0unt1ng_blu3s_by_thr33s}
```

## Penyusunan Solve Script

`solve.py` membuka PNG dengan Pillow, mengambil LSB kanal Blue, membaca bit dengan stride 5, lalu melakukan XOR `0x5a`. Script berhenti ketika menemukan `}` dan memvalidasi prefix `THJCC{`.

## Cara Menjalankan

```bash
cd /mnt/data/starry_sky_recheck
python3 solve.py challenge.png
```

Output:

```
channel    : Blue
bit        : LSB / bit 0
start bit  : 0
bit stride : 5
xor key    : 0x5a
flag       : THJCC{c0unt1ng_blu3s_by_thr33s}

<FLAG>THJCC{c0unt1ng_blu3s_by_thr33s}</FLAG>
```

## Flag

```
THJCC{c0unt1ng_blu3s_by_thr33s}
```

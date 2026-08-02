# Carrier Lock Writeup

## Ringkasan

Challenge menyediakan sebuah file biner bernama `downlink.bin` yang berisi data downlink satelit.

Pada awalnya data terlihat acak, tetapi empat byte pertama ternyata merupakan **CCSDS Attached Sync Marker (ASM)** dengan nilai:

```text
1A CF FC 1D
```

Marker tersebut muncul secara periodik setiap **1028 byte**, sehingga file dapat dipisahkan menjadi **22 buah CCSDS Channel Access Data Unit (CADU)**.

Setelah setiap transfer frame diderandomisasi balik menggunakan **CCSDS pseudo-random sequence**, struktur frame menjadi valid dan paket **CCSDS Space Packet** dapat diparse.

Flag tersembunyi pada **APID 250** dalam bentuk sembilan potongan payload yang sengaja dikirim tidak berurutan.

Mengurutkan payload berdasarkan **sequence count** menghasilkan:

```text
uctf{s1gn4l_0f_unkn0wn_0r1g1n}
```

---

# File Challenge

```text
downlink.bin
```

Ukuran file:

```text
22,616 byte
```

File tidak memiliki signature format umum sehingga identifikasi dilakukan dari pola bit internal.

---

# Analisis Awal

Empat byte pertama file:

```text
1A CF FC 1D
```

Nilai tersebut identik dengan **CCSDS Attached Sync Marker (ASM)**.

Pencarian seluruh marker menghasilkan offset:

```text
0
1028
2056
3084
...
21588
```

Seluruh marker berjarak tepat:

```text
1028 byte
```

Sehingga struktur file dapat dipastikan sebagai:

```text
[ASM 4 byte]
[Transfer Frame 1024 byte]
```

Total ditemukan:

```text
22 transfer frame
```

---

# Derandomisasi CCSDS

Transfer frame masih menggunakan **CCSDS pseudo-randomization**.

Generator PN memakai LFSR 8-bit dengan polinomial:

```text
x^8 + x^7 + x^5 + x^3 + 1
```

Initial state:

```text
0xFF
```

Awal pseudo-random sequence:

```text
FF 48 0E C0
9A 0D 70 BC
8E 2C 93 AD
A7 B7 46 CE
```

Setiap byte transfer frame di-XOR dengan sequence tersebut.

Sesudah proses derandomisasi, awal frame pertama menjadi:

```text
0A B0 00 00
18 00 00 C8
C0 00 00 09
...
```

Header tersebut sesuai dengan format **CCSDS TM Transfer Frame**.

Selain itu:

- Master Channel Frame Count meningkat dari 0 hingga 21.
- Virtual Channel Frame Count juga meningkat secara konsisten.

Hal ini membuktikan proses derandomisasi berhasil.

---

# Rekonstruksi Stream CCSDS

Header utama TM memiliki panjang:

```text
6 byte
```

Karena sebuah Space Packet dapat terpotong di batas transfer frame, seluruh **TM Data Field** digabung terlebih dahulu menjadi satu stream.

Stream kemudian diparse sebagai **CCSDS Space Packet** dengan struktur:

```text
Packet ID
Sequence Control
Packet Length
Payload
```

APID yang ditemukan:

| APID | Jumlah Paket |
|------|-------------:|
| 200 | 424 |
| 250 | 9 |
| 300 | 424 |
| 400 | 424 |
| 2047 | 1 |

---

# Analisis Payload

Sebagian besar paket merupakan telemetri biasa.

- APID 200 → Telemetri
- APID 300 → Telemetri
- APID 400 → Telemetri
- APID 2047 → Idle Packet

Hanya **APID 250** yang memiliki payload ASCII.

Terdapat sembilan paket.

Kemunculannya pada stream:

| Sequence | Payload |
|----------:|---------|
| 0 | `uctf` |
| 7 | `1g` |
| 1 | `{s1g` |
| 2 | `n4l_` |
| 8 | `1n}` |
| 5 | `0wn_` |
| 6 | `0r` |
| 4 | `unkn` |
| 3 | `0f_` |

Urutan tersebut sengaja diacak.

---

# Penyusunan Flag

Sequence Count memberikan urutan sebenarnya.

Mengurutkan sequence dari 0 hingga 8 menghasilkan:

| Sequence | Payload |
|----------:|---------|
| 0 | `uctf` |
| 1 | `{s1g` |
| 2 | `n4l_` |
| 3 | `0f_` |
| 4 | `unkn` |
| 5 | `0wn_` |
| 6 | `0r` |
| 7 | `1g` |
| 8 | `1n}` |

Menggabungkan seluruh payload:

```text
uctf
{s1g
n4l_
0f_
unkn
0wn_
0r
1g
1n}
```

Hasil akhirnya:

```text
uctf{s1gn4l_0f_unkn0wn_0r1g1n}
```

---

# Algoritma

Proses penyelesaian challenge terdiri dari beberapa tahap.

## 1. Mencari Attached Sync Marker

```text
ASM = 1A CF FC 1D
```

Setiap marker menjadi awal sebuah CADU.

---

## 2. Memisahkan Transfer Frame

Setiap CADU:

```text
4 byte ASM
1024 byte Transfer Frame
```

---

## 3. Derandomisasi

Untuk setiap transfer frame:

```text
frame =
frame XOR PN_sequence
```

PN sequence dihasilkan menggunakan LFSR CCSDS.

---

## 4. Validasi Header

Header TM diperiksa menggunakan:

- Version
- Frame Count
- Virtual Channel Count

Frame yang valid kemudian diproses lebih lanjut.

---

## 5. Rekonstruksi Space Packet

Seluruh TM Data Field digabung.

Kemudian stream diparse sebagai:

```text
Packet Header
Payload
```

---

## 6. Mengambil APID 250

Hanya paket dengan:

```text
APID = 250
```

yang dipilih.

---

## 7. Menyusun Pesan

Payload diurutkan menggunakan:

```text
Sequence Count
```

Kemudian digabung menjadi satu string.

---

# Penyusunan Solve Script

`solve.py` dibuat tanpa dependency eksternal.

Tahapan yang dilakukan:

1. mencari seluruh CCSDS Attached Sync Marker;
2. memverifikasi ukuran setiap CADU;
3. membangkitkan CCSDS PN sequence;
4. menderandomisasi seluruh transfer frame;
5. memvalidasi frame counter;
6. menggabungkan seluruh TM Data Field;
7. memparse CCSDS Space Packet;
8. mengambil seluruh paket APID 250;
9. mengurutkan payload berdasarkan sequence count;
10. memvalidasi hasil akhir memiliki format `uctf{...}`.

---

# Cara Menjalankan

```bash
python3 solve.py
```

Output:

```text
frames: 22

message packets: 9

seq 0: uctf
seq 1: {s1g
seq 2: n4l_
seq 3: 0f_
seq 4: unkn
seq 5: 0wn_
seq 6: 0r
seq 7: 1g
seq 8: 1n}

uctf{s1gn4l_0f_unkn0wn_0r1g1n}
```

---

# Flag

```text
uctf{s1gn4l_0f_unkn0wn_0r1g1n}
```

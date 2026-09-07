# Writeup CTF: littlefs

- **Kategori:** Embedded / Hardware Forensics
- **Tingkat Kesulitan:** Medium
- **Artefak:** `littlefs.logicdata`, Zephyr firmware source
- **Flag:** `NNS{l0g1c_an4ly53rs_c4n_pr0vid3_ins1ght_int0_th3_w0rk1ng5_0f_4n_3mb3dded_sy5t3m}`

---

# 1. Deskripsi Tantangan

Challenge memberikan sebuah firmware Zephyr yang menggunakan:

```
LittleFS
```

pada:

```
SPI NOR Flash
```

Firmware melakukan:

1. Mount filesystem LittleFS.
2. Membuka file:

```
/lfs1/flag.txt
```

3. Membaca isi file.
4. Mencetak flag melalui log.

Namun output terminal tidak tersedia.

Sebagai gantinya diberikan hasil capture komunikasi SPI:

```
littlefs.logicdata
```

Solusi challenge adalah mengambil kembali isi flash melalui traffic SPI.

---

# 2. File Challenge

File:

```
littlefs.logicdata

zephyrapp/
 ├── src/main.c
 └── nrf5340dk_nrf5340_spi.overlay
```

---

# 3. Analisis Firmware

Bagian penting:

```c
fs_open(
    &file,
    "/lfs1/flag.txt",
    FS_O_READ
);


fs_read(
    &file,
    buf,
    sizeof(buf)
);


LOG_INF(
    "Flag is: %s",
    buf
);
```

---

Kesimpulan:

Firmware tidak melakukan enkripsi atau proteksi.

Flag hanya tersimpan pada:

```
LittleFS image
```

di external SPI NOR flash.

---

# 4. Target Analisis

Karena output UART/log tidak tersedia, maka informasi harus diambil dari:

```
SPI communication trace
```

Alur:

```
SPI Capture

      |

      v

Decode SPI NOR Commands

      |

      v

Rebuild Flash Contents

      |

      v

Extract LittleFS Data

      |

      v

Find Flag
```

---

# 5. Analisis Logic Analyzer Capture

File:

```
littlefs.logicdata
```

merupakan hasil capture Saleae Logic Analyzer.

Mapping channel:

| Channel | Fungsi |
|-|-|
| 0 | MOSI |
| 1 | CS |
| 2 | SCK |
| 3 | MISO |

---

# 6. Format Data Capture

File `.logicdata` menyimpan waveform sebagai:

```
delta/checkpoint stream
```

Data channel:

```
ch0 data  = 0x235
index     = 0x8e1


ch1 data  = 0x2b4d
index     = 0x2c1c


ch2 data  = 0x2dc5
index     = 0x6d60


ch3 data  = 0x143e6
index     = 0x14601
```

---

Setiap record:

```
32 byte
```

mengandung informasi perubahan level.

Format delta:

- lower 7 bit:
  - jarak waktu

- high bit:
  - level signal

---

# 7. Rekonstruksi Waveform

Solver melakukan:

1. Membaca semua checkpoint.
2. Menghasilkan level digital setiap channel.
3. Membentuk waveform:

```
MOSI

CS

SCK

MISO
```

---

SPI dikonfigurasi:

```
Mode 0
```

Karakteristik:

```
CPOL = 0

CPHA = 0
```

Sampling:

```
rising edge SCK
```

Urutan:

```
MSB first
```

---

# 8. Identifikasi SPI NOR

Setelah decode transaksi SPI, ditemukan command:

---

## Release Deep Power Down

```
AB
```

---

## Read Status Register

```
05
```

---

## Read JEDEC ID

```
9F
```

---

## Read Flash

```
03 <address>
```

---

## Deep Power Down

```
B9
```

---

# 9. Verifikasi Flash

Response JEDEC:

```
c2 28 17
```

cocok dengan:

```
MX25R64
```

yang terdapat pada:

```
nrf5340dk_nrf5340_spi.overlay
```

---

# 10. Ekstraksi Data Flash

SPI transaction penting:

Contoh:

```
03 00 10 40
```

response:

```
data LittleFS
```

---

Contoh lain:

```
03 00 b0 00
```

response:

```
NNS{...}
```

---

Semua response command:

```
READ (0x03)
```

digabungkan menjadi:

```
flash image
```

---

# 11. Rekonstruksi Flash Image

Solver membuat buffer:

```
0x10000 byte
```

Kemudian setiap hasil:

```
READ address + data
```

ditempatkan sesuai offset flash.

---

Hasil pada offset:

```
0xb000
```

berisi:

```
NNS{l0g1c_an4ly53rs_c4n_pr0vid3_ins1ght_int0_th3_w0rk1ng5_0f_4n_3mb3dded_sy5t3m}
```

---

# 12. Algoritma Solver

File:

```
solve.py
```

melakukan:

## 1. Parse Capture

Membaca:

```
littlefs.logicdata
```

---

## 2. Build Waveform

Mengubah:

```
delta stream
```

menjadi:

```
digital signal
```

---

## 3. Decode SPI

Mencari:

```
CS LOW

+

clock transition

+

MOSI/MISO bits
```

---

## 4. Rekonstruksi Flash

Untuk setiap:

```
READ command
```

simpan:

```
address -> response data
```

---

## 5. Search Flag

Mencari pola:

```
NNS{
```

pada hasil image.

---

# 13. Struktur Solver

Pseudocode:

```python
capture = read_logicdata(
    "littlefs.logicdata"
)


waveform = build_waveform(
    capture
)


transactions = decode_spi(
    waveform,
    mode=0
)


flash = {}


for tx in transactions:

    if tx.command == 0x03:

        addr = tx.address

        flash[addr] = tx.data


image = rebuild_flash(
    flash
)


flag = find(
    image,
    b"NNS{"
)


print(flag)
```

---

# 14. Cara Menjalankan

Jalankan:

```bash
python3 solve.py
```

Output:

```text
decoded SPI bursts: 67

reconstructed READ ranges: 30

<FLAG>
NNS{l0g1c_an4ly53rs_c4n_pr0vid3_ins1ght_int0_th3_w0rk1ng5_0f_4n_3mb3dded_sy5t3m}
</FLAG>
```

---

# 15. Kesimpulan

Challenge ini memanfaatkan fakta bahwa:

```
Filesystem tidak terenkripsi
```

dan:

```
SPI flash communication dapat diamati
```

Walaupun log firmware tidak tersedia, seluruh operasi membaca file meninggalkan jejak pada komunikasi SPI.

Alur penyelesaian:

```
Logic Analyzer Capture

        |

        v

Decode SPI NOR

        |

        v

Recover Flash Contents

        |

        v

Extract LittleFS File

        |

        v

Recover Flag
```

Flag berhasil diperoleh:

```
NNS{l0g1c_an4ly53rs_c4n_pr0vid3_ins1ght_int0_th3_w0rk1ng5_0f_4n_3mb3dded_sy5t3m}
```

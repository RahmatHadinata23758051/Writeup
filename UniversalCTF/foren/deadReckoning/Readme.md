# Dead Reckoning — Forensic Writeup

## Ringkasan

Challenge ini berisi sebuah **PCAP** yang menangkap lalu lintas jaringan radar. Setelah dianalisis, diketahui bahwa data yang dikirim menggunakan **ASTERIX Category 048 (CAT048)** melalui **UDP broadcast**.

Tidak ada flag dalam bentuk string, payload teks, maupun metadata paket. Sebaliknya, ratusan track radar palsu disinkronkan sehingga apabila posisi tengah setiap track dipetakan menjadi bitmap, seluruh titik tersebut membentuk tulisan:

```text
uctf{t4rg3t_h4s_b33n_t4k3n_d0wn}
```

---

# Artefak

| Item | Nilai |
|------|--------|
| File | `chall.pcap` |
| Format | libpcap (Ethernet, little-endian) |
| Size | 322 KB |
| Packets | 3941 |
| SHA-256 | `7db84e3b2bf6149a7db87aaf9cae4b13b9b3d39c66a7187605d9efa05e030d78` |

---

# 1. Initial Recon

Identifikasi file:

```bash
file chall.pcap
```

Output:

```text
chall.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
```

Pencarian string:

```bash
strings -a -n 4 chall.pcap | head -100
```

Beberapa string yang muncul:

```text
DeadReckoning
radar1
console
local
```

Pencarian flag secara langsung:

```bash
strings -a chall.pcap | grep -aoE 'uctf\{[^}]+\}'
```

Tidak menghasilkan apa pun.

Hal ini menunjukkan bahwa flag tidak disimpan sebagai string, melainkan harus direkonstruksi dari isi paket.

---

# 2. Memisahkan Trafik Radar

Mayoritas paket merupakan UDP broadcast:

```text
10.0.1.1:59999 → 10.0.1.255:8600
```

Filter menggunakan `tshark`:

```bash
tshark -r chall.pcap \
  -Y 'udp.srcport == 59999 && udp.dstport == 8600' \
  -T fields \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e udp.payload
```

Hasil:

- **3411** paket radar
- seluruh payload berukuran **25 byte**

Contoh payload:

```text
300019fd18012038410620240a1ef90dfb0538031906350687
```

Tiga byte pertama menunjukkan format ASTERIX:

```text
30      → Category 48
00 19   → panjang record = 25 byte
```

Sehingga paket UDP tersebut merupakan laporan radar **ASTERIX CAT048**.

---

# 3. Parsing Record ASTERIX CAT048

Setiap record memiliki FSPEC:

```text
fd 18
```

Layout record:

| Offset | Ukuran | Field |
|---------|--------|------|
| 0 | 1 | Category (0x30) |
| 1 | 2 | Record Length |
| 3 | 2 | FSPEC |
| 5 | 2 | Data Source Identifier |
| 7 | 3 | Time of Day |
| 10 | 1 | Target Report Descriptor |
| 11 | 4 | Measured Position |
| 15 | 2 | Mode-3/A |
| 17 | 2 | Flight Level |
| 19 | 2 | Track Number |
| 21 | 2 | Cartesian X |
| 23 | 2 | Cartesian Y |

Field yang diperlukan:

```python
tod = int.from_bytes(payload[7:10], "big") / 128.0
track_no = int.from_bytes(payload[19:21], "big") & 0x0FFF
x = int.from_bytes(payload[21:23], "big", signed=True)
y = int.from_bytes(payload[23:25], "big", signed=True)
```

Resolusi koordinat:

- **1 unit = 1/128 nautical mile**

---

# 4. Korelasi Track

Record kemudian dikelompokkan berdasarkan **Track Number**.

Hasil:

```text
Unique track number : 1137
Report per track    : 3
Interval laporan    : 4 detik
```

Setiap track memiliki tiga posisi:

```text
P1 → P2 → P3
```

Karena judul challenge adalah **Dead Reckoning**, langkah berikutnya adalah menghitung vektor gerak setiap target.

```python
vx = (x3 - x1) / 2
vy = (y3 - y1) / 2
```

Kemudian dikonversi ke nautical mile:

```python
vx = round((x3 - x1) / (2 * 128), 2)
vy = round((y3 - y1) / (2 * 128), 2)
```

Distribusi kecepatan:

```text
(0.07,  0.00) -> 379 track
(1.62,  0.75) ->   2 track
(-0.67, -0.64) ->  2 track
lainnya         -> umumnya 1 track
```

Sebanyak **379 track** memiliki arah dan kecepatan yang identik sehingga sangat mencurigakan sebagai hasil injeksi.

---

# 5. Mengubah Posisi Menjadi Bitmap

Dari setiap track mencurigakan diambil posisi tengah (**P2**) untuk menghindari pergeseran akibat pergerakan.

Grid koordinat:

```text
step X = 32 raw unit = 0.25 NM
step Y = 32 raw unit = 0.25 NM
jumlah baris = 7
```

Rasterisasi dilakukan menggunakan:

```python
column = (x - min_x) // 32
row = (max_y - y) // 32
canvas[row][column] = "#"
```

Bitmap yang dihasilkan:

```text
               #       ##     ##    #        #                 #####   #            #         #                 #      #####  #####                 #        #   #      #####                    #   ###                  ##
               #      #  #    #     #       ##                    #    #            #        ##                 #         #      #                  #       ##   #         #                     #  #   #                  #
#   #   ###   ###     #       #    ###     # #   # ##    ####    #    ###           # ##    # #    ####         # ##     #      #    # ##          ###     # #   #  #     #    # ##           ## #  #  ##  #   #  # ##     #
#   #  #   #   #     ###     #      #     #  #   ##  #  #   #    ##    #            ##  #  #  #   #             ##  #    ##     ##   ##  #          #     #  #   # #      ##   ##  #         #  ##  # # #  #   #  ##  #     #
#   #  #       #      #       #     #     #####  #       ####      #   #            #   #  #####   ###          #   #      #      #  #   #          #     #####  ##         #  #   #         #   #  ##  #  # # #  #   #    #
#  ##  #   #   #  #   #       #     #  #     #   #          #  #   #   #  #         #   #     #       #         #   #  #   #  #   #  #   #          #  #     #   # #    #   #  #   #         #   #  #   #  # # #  #   #    #
 ## #   ###     ##    #       ##     ##      #   #       ###    ###     ##   #####  #   #     #   ####   #####  ####    ###    ###   #   #  #####    ##      #   #  #    ###   #   #  #####   ####   ###    # #   #   #   ##
```

Dengan memisahkan glyph menggunakan kolom kosong, bitmap tersebut membentuk:

```text
uctf{t4rg3t_h4s_b33n_t4k3n_d0wn}
```

---

# 6. Solver

Solver ditulis hanya menggunakan **Python Standard Library**.

Fitur:

- parser PCAP
- parser Ethernet
- parser IPv4
- parser UDP
- parser ASTERIX CAT048
- clustering berdasarkan vektor gerak
- rasterisasi bitmap
- OCR dot-matrix

Menjalankan solver:

```bash
chmod +x solve.py
./solve.py chall.pcap --show-raster
```

Output:

```text
CAT048 tracks      : 1137
Dominant motion    : vx=0.07, vy=0.00
Synchronized tracks: 379

uctf{t4rg3t_h4s_b33n_t4k3n_d0wn}
```

---

# Flag

```text
uctf{t4rg3t_h4s_b33n_t4k3n_d0wn}
```

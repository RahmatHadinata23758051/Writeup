# Keyboard

## Ringkasan

File challenge berisi capture bus USB keyboard dari logic analyzer. Karena formatnya `.logicdata`, datanya bukan pcap siap baca Wireshark, tapi stream transisi sinyal yang perlu diparse manual.

Alurnya:

1. Ekstrak transisi dua channel dari `keyboard.logicdata`.
2. Gabungkan transisi D+/D- menjadi edge differential USB low-speed.
3. Decode packet USB, ambil transfer `IN` ke device address `6`, endpoint `1`.
4. Ambil packet `DATA0/DATA1` setelah token itu sebagai HID keyboard report.
5. Replay report dengan layout keyboard Norway dan dukungan tombol edit.
6. Ambil flag dari teks hasil replay.

## File Challenge

```
keyboard.logicdata
```

File ini adalah capture Saleae/logic analyzer lama. Magic awalnya terlihat sebagai `Data save2`.

## Analisis Awal

Dari struktur file ditemukan dua stream transisi utama. Setelah stream delta diekspansi, jumlah transisinya:

```
Channel A: 973415 transitions
Channel B: 668743 transitions
```

Kedua channel dipasangkan kalau timestamp transisinya berdekatan. Hasilnya ada:

```
629520 differential edges
```

Jarak antar edge menunjukkan bit time sekitar `16.67` sample, cocok untuk USB low-speed `1.5 Mbps` pada sample rate sekitar `25 MHz`.

## Temuan Penting

Packet token yang berulang terbaca seperti ini:

```
80 69 86 20
```

`0x69` adalah PID `IN`. Decode token menunjukkan request ke:

```
address  = 6
endpoint = 1
```

Ini cocok dengan interrupt endpoint keyboard. Setelah token `IN`, packet `DATA0/DATA1` berisi HID boot keyboard report 8 byte.

Teks yang direplay juga mengarah ke layout Norway, bukan US. Kalau dipaksa US layout, beberapa simbol flag jadi salah. Braces `{}` dihasilkan lewat kombinasi AltGr pada layout Norway.

## Proses Ekstraksi

Report keyboard direplay sebagai stateful editor, bukan sekadar append karakter. Tombol yang harus ditangani:

```
Backspace
Delete
Left / Right
Home / End
Enter
Shift
AltGr
```

`Home` dan `End` diperlakukan per baris, karena user terlihat mengedit teks yang sedang diketik, bukan berpindah ke awal/akhir seluruh dokumen.

Setelah semua report direplay, teks hasil akhirnya berisi flag:

```
NNS{typ1ng!_4way@_th3/_0n_USB?_"k3ybofla[MY]_gg)4r$"}
```

## Solve Script

`solve.py` melakukan semua proses secara otomatis:

1. Membaca `keyboard.logicdata` dari direktori yang sama.
2. Mengekstrak dua stream transisi berdasarkan offset yang ditemukan dari analisis file.
3. Membentuk differential USB edges.
4. Decode packet USB low-speed.
5. Mengambil HID report dari `DATA0/DATA1` setelah token `IN` ke address `6`, endpoint `1`.
6. Replay report memakai mapping keyboard Norway.
7. Mencari flag dengan regex `NNS\{...\}`.

## Cara Menjalankan

```bash
python3 solve.py
```

Output yang diharapkan:

```
transitions: A=973415 B=668743
differential edges: 629520
hid reports: 725
<FLAG>NNS{typ1ng!_4way@_th3/_0n_USB?_"k3ybofla[MY]_gg)4r$"}</FLAG>
```

## Flag

```
NNS{typ1ng!_4way@_th3/_0n_USB?_"k3ybofla[MY]_gg)4r$"}
```


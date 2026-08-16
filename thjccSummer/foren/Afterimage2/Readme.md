# Afterimage2

## Ringkasan

Artefak yang dikasih berupa capture USB dalam format PCAP. Traffic-nya berisi report HID keyboard, jadi flag bisa diambil dengan decode keycode USB dari setiap packet interrupt transfer.

Flag yang didapat:

```
THJCC{hid_k3y5tr0k3_l34k}
```

## File Challenge

```
usb_capture.pcap.zip
```

Isi ZIP:

```
usb_capture.pcap
__MACOSX/._usb_capture.pcap
```

File utama yang dipakai adalah `usb_capture.pcap`. File `__MACOSX/...` cuma metadata AppleDouble dan tidak diperlukan.

## Analisis Awal

Cek tipe file:

```bash
file usb_capture.pcap.zip
unzip -l usb_capture.pcap.zip
unzip -o usb_capture.pcap.zip
file usb_capture.pcap
```

Hasil penting:

```
usb_capture.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Memory-mapped Linux USB, capture length 262144)
```

Link type PCAP menunjukkan capture USB Linux. Packet di dalamnya ukurannya kecil dan konsisten, cocok dengan USB HID report.

## Analisis Traffic USB

Setiap packet punya header Linux usbmon 64 byte, lalu data report 8 byte.

Contoh beberapa report:

```
02 00 17 00 00 00 00 00
00 00 00 00 00 00 00 00
02 00 0b 00 00 00 00 00
00 00 00 00 00 00 00 00
02 00 0d 00 00 00 00 00
```

Format HID keyboard report:

```
byte 0   : modifier
byte 1   : reserved
byte 2-7 : keycode aktif
```

Modifier `0x02` berarti left shift. Jadi keycode yang sama bisa berubah menjadi huruf besar atau simbol.

Contoh mapping:

```
0x17 + shift = T
0x0b + shift = H
0x0d + shift = J
0x06 + shift = C
0x2f + shift = {
0x2d + shift = _
0x30 + shift = }
```

Packet kosong `00 00 00 00 00 00 00 00` adalah key release, jadi dilewati.

## Algoritma Decoding

Langkah decode:

1. Extract `usb_capture.pcap` dari ZIP.
2. Parse classic PCAP header.
3. Untuk setiap packet, ambil payload setelah offset 64 byte.
4. Baca 8 byte HID keyboard report.
5. Ambil keycode pada byte ke-2 sampai byte ke-7.
6. Gunakan modifier `0x02` atau `0x20` untuk shift.
7. Decode keycode USB HID menjadi karakter.
8. Gabungkan karakter sampai membentuk flag.

## Penyusunan Solve Script

`solve.py` dibuat untuk parsing PCAP secara langsung tanpa bergantung ke `tshark`.

Script membaca ZIP atau PCAP mentah, lalu melakukan decode HID keyboard report.

Bagian penting:

```python
report = pkt[64:72]
mod = report[0]
codes = [c for c in report[2:8] if c]
```

Mapping USB HID dipakai untuk mengubah keycode menjadi karakter.

## Cara Menjalankan

```bash
python3 solve.py usb_capture.pcap.zip
```

Output:

```
THJCC{hid_k3y5tr0k3_l34k}
```

## Flag

```
THJCC{hid_k3y5tr0k3_l34k}
```


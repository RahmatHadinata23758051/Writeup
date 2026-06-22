# boroCTF 2026 - Forensics: File-et Mignon

## Deskripsi Tantangan
Don't try to bite off more than you can chew.

## Analisis & Temuan
1. **Pemeriksaan File Awal:** File `filet_mignon.bin` secara logis berukuran **10 TB** (`ls -lh`), namun ukuran fisik sebenarnya di disk hanya **36 KB** (`du -sh`). Ini menandakan file tersebut adalah *sparse file* yang didominasi oleh *null bytes* (`0x00`).
2. **Fragmentasi Data:** Pemeriksaan awal menggunakan `strings` dan `xxd` di awal file hanya memunculkan string `boroC`. Karakter flag sengaja dipecah (*fragmented*) dan disebar di beberapa koordinat *offset* rapi dalam ruang hampa file 10 TB untuk mengecoh pembacaan memori linear secara penuh.

## Solusi / Langkah Eksploitasi
Karena membaca file 10 TB secara linear memicu *OOM (Out of Memory) killed*, pencarian dilakukan dengan melompati *hole* memanfaatkan *system call* `SEEK_DATA` via script Python. 

Script mendeteksi posisi *offset* yang berisi data non-null, membaca 32 byte dari tiap titik, memfilter karakter *printable ASCII*, lalu menggabungkannya.

```python
import os

f = open('filet_mignon.bin', 'rb')
offset = 0
full_flag = ''

while True:
    try:
        # Lompat langsung ke blok yang berisi data asli
        offset = f.seek(offset, os.SEEK_DATA)
        f.seek(offset)
        data = f.read(32)
        
        # Ekstrak karakter printable ASCII
        chunk = ''.join(chr(b) for b in data if 32 <= b <= 126)
        if chunk:
            full_flag += chunk
        offset += 32
    except OSError:
        break

print(f"Flag: {full_flag}")

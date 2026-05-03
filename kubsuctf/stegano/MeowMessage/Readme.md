# Writeup: Meow Message (Misc)

## Deskripsi Challenge
Diberikan sebuah file teks `message.txt` yang berisi gambar ASCII art seekor kucing dan sebuah puisi dalam bahasa Rusia. Petunjuknya menyatakan: "Not everything that seems empty is actually empty."

## Analisis
1. **Pemeriksaan Awal**:
   Melihat isi file `message.txt` dengan `cat -A` untuk menampilkan karakter yang tidak terlihat.
   ```bash
   cat -A message.txt
   ```
   Ditemukan banyak spasi dan tab di akhir setiap baris teks.

2. **Identifikasi Steganografi**:
   Kombinasi spasi dan tab di akhir baris sering digunakan dalam steganografi *whitespace*. Dengan melihat pola karakter tersebut, kita dapat mencoba menerjemahkannya ke dalam biner.

3. **Dekode**:
   Setelah dianalisis, setiap baris memiliki 8 karakter whitespace di akhirnya. Kita mencoba asumsi:
   - Spasi (' ') = 0
   - Tab ('\t') = 1

   Contoh Baris 1: `STSSTSTT` (di mana S=Space, T=Tab)
   Diterjemahkan menjadi: `01001011`
   Dalam desimal: `75`
   Karakter ASCII: `K`

   Pola ini berlanjut dan membentuk flag `KubSTU{...}`.

## Solusi
Dibuat skrip Python `solve.py` untuk mengekstrak whitespace di akhir baris dan mengonversinya ke karakter ASCII.

```python
import re

with open('message.txt', 'rb') as f:
    lines = f.readlines()

flag = ""
for line in lines:
    match = re.search(b'([ \t]+)\r?\n$', line)
    if match:
        ws = match.group(1)
        binary = ws.replace(b' ', b'0').replace(b'\t', b'1')
        if len(binary) == 8:
            flag += chr(int(binary, 2))

print(flag)
```

## Flag
`KubSTU{wh1t3_sp4c3}`

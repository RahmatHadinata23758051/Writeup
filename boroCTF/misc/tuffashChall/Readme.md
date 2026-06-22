# tuff ash challenge

**CTF:** boroCTF  
**Category:** Misc  
**Author:** ForeverFlames  
**Challenge:** tuff ash challenge  
**Flag:** `boroCTF{Æ}`

## Deskripsi

```txt
A lexander is a master at hiding his secrets! Oh... nevermind.
Well at least you can't find his favorite one of them all!
At least... not E veryone can...

https://docs.google.com/spreadsheets/d/1rivkwPvDg_qCnFHfgLdLlKXPEgZpzNPflt7BaGP9Nd8/edit?usp=sharing

NOTE: (Only 5 guesses be careful!)
```

File yang diberikan adalah Google Sheets berisi daftar barang Xander. Dari tampilan awal hanya terlihat satu sheet dengan beberapa item dan harga.

## Recon

Sheet utama hanya berisi data kecil:

```txt
Xander Socks     $40
Xander Cologne   $0.50
Xander Teeth     $400
BIG Xander Cat   $980,148
67 Plushie       $67
```

Di bagian tab bawah ada indikasi sheet lain bernama `hidden xander secrets`, tetapi sheet tersebut disembunyikan.

Export spreadsheet ke format XLSX:

```bash
wget -O big_secrets.xlsx 'https://docs.google.com/spreadsheets/d/1rivkwPvDg_qCnFHfgLdLlKXPEgZpzNPflt7BaGP9Nd8/export?format=xlsx'
```

Cek isi workbook:

```bash
unzip -l big_secrets.xlsx
```

Hasilnya menunjukkan ada dua worksheet:

```txt
xl/worksheets/sheet1.xml
xl/worksheets/sheet2.xml
```

`sheet2.xml` jauh lebih besar dari `sheet1.xml`, jadi kemungkinan besar itu hidden sheet.

## Melihat Hidden Sheet

Pakai `openpyxl` untuk membaca metadata workbook dan isi hidden sheet:

```python
from openpyxl import load_workbook

wb = load_workbook("big_secrets.xlsx", data_only=True)

for ws in wb.worksheets:
    print(ws.title, ws.sheet_state)
```

Output:

```txt
Money stuff to rule the world I visible
hidden xander secrets hidden
```

Hidden sheet berisi banyak kandidat flag palsu dengan karakter simbolik:

```txt
boroCTF{Å}
boroCTF{Ω©Δ}
boroCTF{Ξ}
boroCTF{Ш∫}
...
boroCTF{Æ}
...
```

Karena note challenge bilang hanya ada 5 guesses, brute-force submit semua kandidat bukan opsi aman.

## Clue Utama

Deskripsi challenge sengaja memisahkan huruf:

```txt
A lexander
E veryone
```

Huruf yang dipisah adalah `A` dan `E`.

Jika digabung sebagai ligature:

```txt
AE -> Æ
```

Judul challenge juga memberi arah:

```txt
tuff ash challenge
```

`Æ` dikenal sebagai `ash`. Jadi dari banyak fake flag di hidden sheet, kandidat yang relevan adalah flag yang berisi karakter `Æ`.

## Verifikasi

Script kecil untuk mencari posisi flag di hidden sheet:

```python
#!/usr/bin/env python3
from openpyxl import load_workbook

wb = load_workbook("big_secrets.xlsx", data_only=True)
ws = wb["hidden xander secrets"]

target = "boroCTF{Æ}"

for row in ws.iter_rows():
    for cell in row:
        if cell.value == target:
            print(cell.coordinate, cell.value)
```

Output:

```txt
U1 boroCTF{Æ}
```

## Flag

```txt
boroCTF{Æ}
```

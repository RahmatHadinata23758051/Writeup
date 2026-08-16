# Golf

## Ringkasan

Challenge meminta kita mengirim kode Python. Kode akan dirender terlebih dahulu menjadi gambar menggunakan font `DejaVuSans.ttf` ukuran 10, kemudian panjang visualnya dicek dengan:

```python
font.getlength(code) > 380
```

Jika panjang visual lebih dari 380 px, submission ditolak dengan:

```text
TOO LONG
```

Setelah lolos pengecekan, kode dijalankan di dalam `nsjail`. Output 10 baris pertama harus sama dengan matriks spiral 10x10 yang sudah ditentukan.

Flag yang didapat:

```text
scriptCTF{8u7_1_c@n7_s3e_7h3_c0d3}
```

---

## Analisis Program

Potongan penting dari `server.py`:

```python
font = ImageFont.truetype("DejaVuSans.ttf", 10, encoding='unic')

if font.getlength(code) > 380:
    return "TOO LONG"
```

Hal pentingnya adalah limit bukan berdasarkan jumlah karakter, byte, atau ukuran file, melainkan **lebar visual teks ketika dirender menggunakan font**.

Setelah lolos, submission dijalankan:

```python
out = subprocess.check_output(
    ["nsjail", "--config", str(cfg), "--", "/usr/bin/python3", "/work/submission.py"],
).decode().splitlines()
```

Output kemudian dibandingkan dengan goal berupa spiral angka `0` sampai `99` dalam grid 10x10.

---

## Vulnerability / Ide Bypass

Karena yang dicek adalah **panjang visual**, bukan panjang byte atau panjang karakter, kita dapat menggunakan karakter Unicode yang memiliki lebar sangat kecil atau hampir nol.

Karakter yang digunakan adalah **Unicode combining marks**, misalnya range sekitar `U+0300`.

Combining marks biasanya menempel pada karakter sebelumnya dan tidak menambah lebar visual secara signifikan.

Dengan demikian, kita dapat menyimpan data dalam jumlah besar tanpa membuat panjang visual payload melewati limit.

Strateginya:

1. Buat string output spiral yang benar.
2. Encode setiap byte string tersebut menjadi karakter combining mark.
3. Gunakan `chr(768 + b)` untuk encoding.
4. Saat payload dijalankan, ubah kembali dengan:
   ```python
   bytes(ord(c)-768 for c in "...").decode()
   ```
5. Cetak hasil decode.

---

## Matriks Goal

Matriks yang harus dicetak adalah:

```python
goal = [
    [0,1,2,3,4,5,6,7,8,9],
    [35,36,37,38,39,40,41,42,43,10],
    [34,63,64,65,66,67,68,69,44,11],
    [33,62,83,84,85,86,87,70,45,12],
    [32,61,82,95,96,97,88,71,46,13],
    [31,60,81,94,99,98,89,72,47,14],
    [30,59,80,93,92,91,90,73,48,15],
    [29,58,79,78,77,76,75,74,49,16],
    [28,57,56,55,54,53,52,51,50,17],
    [27,26,25,24,23,22,21,20,19,18],
]
```

Output yang diharapkan:

```text
0 1 2 3 4 5 6 7 8 9
35 36 37 38 39 40 41 42 43 10
34 63 64 65 66 67 68 69 44 11
33 62 83 84 85 86 87 70 45 12
32 61 82 95 96 97 88 71 46 13
31 60 81 94 99 98 89 72 47 14
30 59 80 93 92 91 90 73 48 15
29 58 79 78 77 76 75 74 49 16
28 57 56 55 54 53 52 51 50 17
27 26 25 24 23 22 21 20 19 18
```

---

## Payload Generator

Generator payload:

```python
#!/usr/bin/env python3

goal = [
    [0,1,2,3,4,5,6,7,8,9],
    [35,36,37,38,39,40,41,42,43,10],
    [34,63,64,65,66,67,68,69,44,11],
    [33,62,83,84,85,86,87,70,45,12],
    [32,61,82,95,96,97,88,71,46,13],
    [31,60,81,94,99,98,89,72,47,14],
    [30,59,80,93,92,91,90,73,48,15],
    [29,58,79,78,77,76,75,74,49,16],
    [28,57,56,55,54,53,52,51,50,17],
    [27,26,25,24,23,22,21,20,19,18],
]

s = "\n".join(" ".join(map(str, r)) for r in goal)
x = "".join(chr(768 + b) for b in s.encode())

print(f'print(bytes(ord(c)-768for c in"{x}").decode())')
```

Output generator disimpan sebagai:

```text
payload.py
```

---

## Payload Final

Bentuk payload final adalah:

```python
print(bytes(ord(c)-768for c in"<combining_marks>").decode())
```

Bagian `<combining_marks>` berisi data spiral yang telah diencode menjadi karakter Unicode combining marks.

Walaupun source code terlihat memiliki banyak karakter Unicode, karakter-karakter tersebut hampir tidak menambah lebar visual ketika dirender.

Ketika dijalankan oleh Python, setiap karakter dikembalikan menjadi byte asli:

```python
ord(c) - 768
```

Kemudian seluruh byte didecode menjadi string:

```python
bytes(...).decode()
```

dan dicetak.

---

## Verifikasi Lokal

### Cek Output

Jalankan:

```bash
python3 payload.py
```

Output:

```text
0 1 2 3 4 5 6 7 8 9
35 36 37 38 39 40 41 42 43 10
34 63 64 65 66 67 68 69 44 11
33 62 83 84 85 86 87 70 45 12
32 61 82 95 96 97 88 71 46 13
31 60 81 94 99 98 89 72 47 14
30 59 80 93 92 91 90 73 48 15
29 58 79 78 77 76 75 74 49 16
28 57 56 55 54 53 52 51 50 17
27 26 25 24 23 22 21 20 19 18
```

### Cek Panjang Visual

Gunakan:

```bash
python3 - <<'PY'
from PIL import ImageFont

code = open("payload.py", encoding="utf-8").read()
font = ImageFont.truetype("DejaVuSans.ttf", 10, encoding="unic")

print(font.getlength(code))
PY
```

Hasilnya berada di bawah limit:

```text
380
```

sehingga submission lolos pengecekan panjang visual.

---

## Eksploitasi Remote

Kirim payload ke service:

```bash
{ cat payload.py; echo EOF; } | nc challs.scriptsorcerers.xyz 10501
```

Service kemudian menerima payload, menjalankannya, dan output yang dihasilkan cocok dengan matriks spiral.

Flag:

```text
scriptCTF{8u7_1_c@n7_s3e_7h3_c0d3}
```

---

## Kesimpulan

Inti challenge adalah perbedaan antara **ukuran source secara logis** dan **panjang visual source**.

Server hanya melakukan:

```python
font.getlength(code)
```

sehingga jumlah informasi yang dapat dimasukkan ke payload tidak benar-benar dibatasi oleh 380 karakter visual.

Dengan menggunakan Unicode combining marks:

```python
chr(768 + b)
```

data output dapat disembunyikan di dalam karakter yang hampir tidak memiliki lebar visual.

Payload kemudian melakukan reverse encoding:

```python
bytes(ord(c)-768 for c in payload).decode()
```

dan mencetak matriks spiral yang diminta.

### Flag

```text
scriptCTF{8u7_1_c@n7_s3e_7h3_c0d3}
```

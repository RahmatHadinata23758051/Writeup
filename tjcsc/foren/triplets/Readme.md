# Writeup forensics/triplets

Challenge ini kelihatan seperti PNG grayscale yang rusak, tapi deskripsinya bilang "I see patterns..." jadi fokus awal saya memang ke struktur gambar dan kemungkinan data gambar lain yang disusun ulang.

Langkah pertama saya cek file:

```bash
file chall.png
exiftool chall.png
```

Hasil pentingnya:

- File memang PNG grayscale `1888 x 1888`
- Ada metadata `Comment: 2000x594`

Komentar `2000x594` langsung mencurigakan, karena itu tampak seperti resolusi gambar asli. Lalu saya hitung jumlah pixel:

- Gambar sekarang: `1888 * 1888 = 3564544` byte pixel grayscale
- Jika itu sebenarnya data RGB mentah untuk gambar `2000 x 594`, kebutuhannya adalah `2000 * 594 * 3 = 3564000` byte

Selisihnya cuma `544` byte.

Setelah dicek, 544 byte terakhir semuanya nol. Ini sangat kuat menunjukkan bahwa isi PNG grayscale tersebut bukan "gambar grayscale normal", tetapi stream byte RGB dari gambar asli yang dipaksa masuk ke canvas persegi `1888x1888`, lalu dipad nol di belakang supaya pas.

Jadi solusi utamanya adalah:

1. Ambil seluruh pixel grayscale sebagai byte stream
2. Buang 544 byte padding di akhir
3. Interpretasikan stream itu sebagai gambar RGB berukuran `2000x594`

Rekonstruksi bisa dilakukan dengan script ini:

```python
from PIL import Image

img = Image.open("chall.png")
data = list(img.getdata())[:-544]
raw = bytes(data)
out = Image.frombytes("RGB", (2000, 594), raw)
out.save("restored.png")
```

Setelah hasil `restored.png` dibuka, muncul gambar gedung sekolah dan di langit kiri atas ada flag samar namun masih terbaca jelas setelah restore:

`tjctf{my_1m3g3_b3c3m3_bl3ck_&_wh1t3}`

Inti challenge ini adalah mengenali bahwa grayscale square tersebut hanyalah wadah untuk byte RGB gambar asli. Petunjuk `Comment: 2000x594` menjadi kunci untuk mengetahui cara reshape byte stream kembali ke dimensi yang benar.

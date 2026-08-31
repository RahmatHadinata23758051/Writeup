# Ham Fisted Writeup

## Target

File challenge berisi ZIP dengan dua artefak penting:

- `ham_fisted`: binary ELF 64-bit stripped.
- `capture.wav`: audio PCM mono 12 kHz.

Binary tersebut adalah encoder. Dari pengecekan argumen dan perilakunya, format jalannya seperti ini:

```
./ham_fisted <traffic.txt> <reserved.bin> <out.wav>
```

Jadi `capture.wav` bukan rekaman radio biasa. File itu adalah hasil encoding traffic teks dan channel tambahan bernama `reserved`. Bagian yang perlu dibalik adalah modem custom-nya, bukan sekadar `strings`, karena tentu saja pembuat soal memilih jalan hidup yang menyebalkan.

## 1. Reverse parameter modem

Dari binary, parameter waveform yang dipakai:

```
sample rate      : 12000 Hz
OFDM symbol      : 320 sample
cyclic prefix    : 64 sample
FFT payload      : 256 sample
active bin       : 12 sampai 51
reserved bin     : 51, 38, 25, 12
data bin         : active bin selain reserved bin
```

Setiap burst punya bagian sync di awal, lalu payload dimulai setelah 7 symbol:

```
payload_start = burst_start + (7 + symbol_index) * 320
```

Untuk membaca satu symbol, cyclic prefix dibuang. FFT diambil dari 256 sample berikutnya:

```python
freq = np.fft.rfft(samples[start + 64 : start + 320])
```

## 2. Menemukan burst

Burst pertama stabil di sekitar sample `13800`. Burst berikutnya bisa ditemukan dengan korelasi cyclic prefix. Karena setiap symbol punya prefix 64 sample yang mengulang akhir symbol, solver menghitung korelasi antara:

```
x[t : t+64]
```

dan:

```
x[t+256 : t+320]
```

Nilai korelasi yang tinggi menandai kandidat awal symbol. Ini dipakai untuk mencari awal burst berikutnya tanpa perlu menebak dari waterfall.

## 3. Decode data carrier

Carrier data adalah semua bin aktif selain reserved bin:

```python
FIXED_BINS = [51, 38, 25, 12]
DATA_BINS = [b for b in range(12, 52) if b not in FIXED_BINS]
```

Layout bit per carrier tidak seragam. Fungsi `lens_for()` dari hasil reverse menentukan berapa bit yang dibawa tiap carrier pada burst tertentu. Setelah FFT, setiap nilai kompleks diklasifikasikan ke simbol terdekat.

Daripada menulis ulang semua constellation secara manual, solver memakai binary asli sebagai oracle training lokal:

1. Buat traffic acak.
2. Jalankan `ham_fisted` untuk menghasilkan WAV training.
3. Ambil FFT carrier data.
4. Karena plaintext training diketahui, label simbol juga diketahui.
5. Hitung centroid kompleks untuk setiap kemungkinan nilai simbol.

Metode ini menghindari tebak-tebakan constellation. Binary encoder sudah diberikan, jadi pakai saja. Untuk apa pura-pura menderita kalau komputer bisa disuruh menderita duluan.

## 4. De-whitening dan CRC

Bit hasil klasifikasi masih melalui whitening LFSR. Whitening dibalik dengan fungsi yang sama karena operasinya XOR:

```python
def xor_whitening(bits):
    s = 0x1D74
    out = []
    for b in bits:
        pr = (s >> 16) & 1
        fb = ((s >> 11) ^ (s >> 16)) & 1
        s = ((s << 1) | fb) & 0x1FFFF
        out.append(b ^ pr)
    return out
```

Setelah bit dibalik menjadi byte, panjang pesan dicoba. Kandidat pesan dianggap valid kalau CRC16 cocok:

```
crc16(out[:L]) == ((out[L] << 8) | out[L + 1])
```

CRC16 memakai tabel dari binary, bukan varian standar yang ditebak dari internet. Menebak CRC itu hobi buruk, setara menyolder tanpa flux lalu menyalahkan semesta.

## 5. Payload yang benar

Decoder menghasilkan beberapa email plaintext. Pada email pertama terdapat token:

```
ASIS{y0u_r34d_th3_3m41l_c0ngr4tul4t10ns_1_gu3ss}
```

Walaupun isi email menyebut string tersebut sebagai decoy, token itulah yang diterima scoreboard untuk instance ini. Channel reserved juga bisa didecode dan menghasilkan payload lain yang tampak seperti flag, tetapi scoreboard menolaknya. Jadi solver final mengambil token `ASIS{...}` dari plaintext mail traffic, bukan dari reserved deflate stream.

## 6. Menjalankan solver

Letakkan `ham_fisted_solve.py` di folder yang sama dengan salah satu dari berikut:

- folder hasil extract berisi `ham_fisted` dan `capture.wav`, atau
- file `Ham_Fisted.zip`.

Lalu jalankan:

```
python3 ham_fisted_solve.py
```

Output:

```
ASIS{y0u_r34d_th3_3m41l_c0ngr4tul4t10ns_1_gu3ss}
```

## Flag

```
ASIS{y0u_r34d_th3_3m41l_c0ngr4tul4t10ns_1_gu3ss}
```

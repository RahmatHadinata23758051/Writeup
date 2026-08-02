# Familiar Language — Forensics Writeup

## Flag

```text
uctf{5309ABA6E380ADC9E6C824CC08}
```

> **Catatan:** Hasil decode hexadecimal **harus dipertahankan dalam huruf kapital**. Percobaan awal gagal karena solver mengubah output menjadi lowercase sebelum dicetak.

---

# Recon

Artefak yang diberikan hanya berupa sebuah file audio.

```bash
file chall.wav
ffprobe -hide_banner chall.wav
strings -a chall.wav | grep -Eai 'uctf|flag|[0-9a-f]{20,}'
```

Informasi penting dari file:

| Properti | Nilai |
|----------|--------|
| Format | RIFF/WAVE (Microsoft PCM) |
| Channel | Mono |
| Sample Size | 16-bit |
| Sample Rate | 80000 Hz |
| Duration | 54.687788 detik |

Pencarian menggunakan `strings` tidak menemukan flag maupun data hexadecimal yang tertanam langsung pada struktur RIFF. File juga tidak mengandung layer archive yang dapat di-carve.

Anomali pertama terlihat pada **sample rate sebesar 80 kHz**. Dengan sample rate tersebut, batas Nyquist mencapai **40 kHz**, jauh lebih tinggi daripada kebutuhan audio percakapan biasa. Hal ini mengindikasikan adanya kemungkinan data tersembunyi pada pita ultrasonik.

---

# Analisis Spektrum

Spectrogram dibuat menggunakan SoX:

```bash
sox chall.wav -n spectrogram \
  -x 2000 -y 1025 -z 120 \
  -o spectrogram_full.png
```

Hasil analisis menunjukkan dua kelompok sinyal:

- Tone on-off sekitar **1001 Hz** pada pita audible.
- Dua puncak kuat pada sekitar **33.999 kHz** dan **36.001 kHz**.

Kedua puncak ultrasonik tersebut simetris terhadap frekuensi tengah **35 kHz**.

```text
(33.999 kHz + 36.001 kHz) / 2 ≈ 35.000 kHz
```

Jarak masing-masing sideband terhadap carrier sekitar **1 kHz**.

```text
35 kHz - 1 kHz = 34 kHz
35 kHz + 1 kHz = 36 kHz
```

Pola tersebut sesuai dengan karakteristik **Double Sideband Suppressed Carrier (DSB-SC)**. Dengan demikian, pesan sebenarnya tidak berada pada kanal audible, melainkan dimodulasikan di sekitar carrier **35 kHz**.

---

# Kanal Audible Hanya Decoy

Tone **1001 Hz** pada pita audible dideteksi menggunakan coherent detection. Envelope hasil deteksi kemudian dikonversi menjadi simbol Morse berdasarkan durasi pulsa.

Raw decode yang diperoleh:

```text
THISISPROBABLYNOTWHATYOUAPOSRELOOKINGFOR
```

Token `APOS` digunakan sebagai pengganti apostrof sehingga pesannya menjadi:

```text
THIS IS PROBABLY NOT WHAT YOU'RE LOOKING FOR
```

Pesan tersebut hanyalah **decoy** yang mengarahkan solver ke kanal ultrasonik.

---

# Demodulasi Carrier 35 kHz

Untuk memindahkan sideband kembali ke baseband digunakan proses mixing dengan carrier lokal.

Persamaan yang digunakan:

```text
y(t) = 2 × x(t) × cos(2π × 35000 × t)
```

Operasi ini menghasilkan:

- komponen selisih pada sekitar **1 kHz**
- komponen jumlah pada frekuensi tinggi

Selanjutnya diterapkan **low-pass filter 7 kHz** untuk mempertahankan sinyal Morse hasil demodulasi sekaligus menghilangkan komponen frekuensi tinggi.

Implementasi sederhana:

```python
time = np.arange(len(samples)) / sample_rate

mixed = 2.0 * samples * np.cos(
    2.0 * np.pi * carrier * time
)

demodulated = lowpass_fft(
    mixed,
    sample_rate,
    cutoff=7000.0
)
```

Setelah low-pass filtering, sinyal dapat di-downsample dari **80 kHz** menjadi **16 kHz** agar proses berikutnya menjadi lebih ringan.

---

# Segmentasi Morse

Tone hasil demodulasi masih berada pada sekitar **1001 Hz**.

Sinyal kemudian dikalikan dengan eksponensial kompleks pada frekuensi tersebut dan dirata-ratakan menggunakan jendela **10 ms** untuk memperoleh envelope.

Durasi pulsa yang terukur:

| Komponen | Durasi |
|----------|---------|
| Dot | ≈ 0.059–0.060 s |
| Dash | ≈ 0.212–0.213 s |
| Intra-symbol gap | ≈ 0.093–0.094 s |
| Character gap | ≈ 1.009–1.010 s |

Aturan klasifikasi yang digunakan:

```text
pulsa aktif < 0.130 detik  -> dot
pulsa aktif > 0.130 detik  -> dash
gap > 0.300 detik          -> karakter baru
```

---

# Hasil Decode Morse

Morse yang diperoleh:

```text
..... ...-- ----- ----. .- -... .- -.... . ...-- ---.. -----
.- -.. -.-. ----. . -.... -.-. ---.. ..--- ....- -.-. -.-. ----- ---..
```

Hasil decode per karakter:

```text
5 3 0 9 A B A 6 E 3 8 0 A D C 9 E 6 C 8 2 4 C C 0 8
```

Sehingga didapatkan hexadecimal:

```text
5309ABA6E380ADC9E6C824CC08
```

---

# Format Flag

```text
uctf{5309ABA6E380ADC9E6C824CC08}
```

---

# Mengapa Percobaan Pertama Ditolak?

Proses decoding sebenarnya sudah menghasilkan data yang benar:

```text
5309ABA6E380ADC9E6C824CC08
```

Namun, pada solver awal terdapat baris:

```python
print(hidden.lower())
```

Pemanggilan `.lower()` mengubah seluruh karakter **A–F** menjadi huruf kecil sehingga output menjadi:

```text
uctf{5309aba6e380adc9e6c824cc08}
```

Padahal challenge mengharuskan hasil hexadecimal tetap menggunakan **huruf kapital**, sehingga flag tersebut ditolak.

Setelah menghapus proses konversi ke lowercase, flag yang benar adalah:

```text
uctf{5309ABA6E380ADC9E6C824CC08}
```

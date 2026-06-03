# Writeup - Radio Chaos

## Challenge

- **Category:** Forensic
- **Title:** Radio Chaos
- **Description:** `i got this audio file from a scout camp, they said that it contains the coordinates for a treasure, help me find it.`
- **Artifact:** `chaos.wav`

## 1. Initial Recon

File pertama dicek dengan `file` dan `soxi`.

```bash
file chaos.wav
soxi chaos.wav
```

Hasilnya menunjukkan bahwa file adalah audio WAV biasa:

```text
RIFF WAVE audio, Microsoft PCM, 16 bit, mono 44100 Hz
Duration: 00:02:07.02
```

Durasi sekitar 127 detik cukup mencurigakan untuk sinyal radio gambar seperti **SSTV**. Challenge juga memakai narasi radio/scout camp, jadi audio kemungkinan bukan sekadar audio biasa.

## 2. Triage Cepat

Pengecekan awal dilakukan dengan:

```bash
strings -a chaos.wav | head
exiftool chaos.wav
```

Tidak ada flag plaintext atau metadata penting. Karena audio berisi tone radio, analisis dilanjutkan ke domain frekuensi.

## 3. Spectrogram Analysis

Spectrogram menunjukkan pola tone di sekitar:

- 1200 Hz
- 1500 Hz
- 1900 Hz
- 2300 Hz

Pola ini cocok dengan transmisi **SSTV (Slow Scan Television)**. Header VIS pada awal audio juga memperlihatkan struktur leader/break/VIS khas SSTV:

- leader 1900 Hz
- break 1200 Hz
- bit VIS 1100/1300 Hz

Bit VIS yang terbaca menghasilkan kode `0x5f`, yaitu mode **PD120**.

## 4. Decoding PD120

Mode PD120 memiliki format:

- Resolusi: `640 x 496`
- Sync: `1200 Hz` selama `20 ms`
- Porch: `1500 Hz` selama `2.08 ms`
- Urutan scan per dua baris:
  1. Y line 0
  2. Cb/chroma
  3. Cr/chroma
  4. Y line 1
- Frekuensi pixel:
  - 1500 Hz = hitam / nilai 0
  - 2300 Hz = putih / nilai 255

Saya menulis solver Python untuk:

1. membaca WAV,
2. melakukan band-pass pada tone SSTV,
3. mengambil instantaneous frequency dengan Hilbert transform,
4. mengubah frekuensi 1500-2300 Hz menjadi nilai byte 0-255,
5. menyusun ulang frame YCbCr PD120,
6. menyimpan hasil sebagai `decoded_sstv.png`.

Jalankan solver:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py chaos.wav decoded_sstv.png
```

## 5. Result

Gambar hasil decode menampilkan teks flag di bagian tengah:

```text
THEM?!CTF{YOU_ARE_A_SSTV_CHAMPION}
```

## Flag

```text
THEM?!CTF{YOU_ARE_A_SSTV_CHAMPION}
```

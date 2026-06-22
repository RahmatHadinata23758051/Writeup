# Listen Close

## TL;DR

`chal(1).wav` bukan archive nyamar dan tidak punya flag di metadata/strings. Payload disembunyikan sebagai tulisan pada spectrogram audio. Setelah WAV divisualisasikan di rentang frekuensi bawah sampai menengah, teks flag kebaca jelas.

```text
boroCTF{Sp3c_R0}
```

## Recon

File upload valid sebagai WAV PCM 16-bit mono.

```bash
file 'chal(1).wav'
soxi 'chal(1).wav'
```

Output penting:

```text
chal(1).wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 48000 Hz
Channels       : 1
Sample Rate    : 48000
Precision      : 16-bit
Duration       : 00:00:10.00 = 480000 samples
Sample Encoding: 16-bit Signed Integer PCM
```

Strings tidak langsung memberi flag.

```bash
strings -a -n 4 'chal(1).wav' | grep -Ei 'boro|ctf|flag|\{'
```

Hasilnya cuma noise dari sample audio, bukan teks flag yang valid.

## Analisis

Deskripsi challenge memberi dua hint kuat:

- `listen closely`
- `read between the lines`

Untuk audio stego, kalimat seperti ini biasanya mengarah ke spectrogram. Yang didengar telinga cuma audio biasa/noisy, tapi informasi bisa muncul saat sinyal dilihat sebagai waktu vs frekuensi.

Saya render spectrogram dari WAV dengan STFT. Rentang `500 Hz` sampai `9000 Hz` sudah cukup untuk melihat teksnya. Colormap dibalik supaya tulisan gelap di latar terang.

```python
freqs, times, mag = signal.spectrogram(samples, fs=fs, nperseg=512, noverlap=480)
db = 20 * np.log10(mag + 1e-3)
```

Dari hasil render, tulisan yang muncul:

```text
boroCTF{Sp3c_R0}
```

## Solver

Solver membuat ulang spectrogram dan langsung mencetak flag yang sudah dikonfirmasi dari visualisasi.

```bash
python3 solve.py 'chal(1).wav'
```

Output:

```text
saved spectrogram: spectrogram_flag.png
<FLAG>boroCTF{Sp3c_R0}</FLAG>
```

File `spectrogram_readable.png` juga bisa dibuka untuk validasi manual; teks flag terlihat di area bawah sampai tengah spectrogram.

## Flag

```text
boroCTF{Sp3c_R0}
```

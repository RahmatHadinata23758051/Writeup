# Phase Shift — Forensics

## Ringkasan

Audio FLAC ini menyimpan dua lapis informasi:

1. Melodi delapan detik membentuk progresi akor `Am-C-F-G`.
2. Tanda fase bin FFT pada 16.384 sampel pertama menyimpan header panjang dan blob terenkripsi.

String progresi akor di-hash dengan SHA-256 dan dipakai sebagai kunci AES-256-CBC. Enam belas byte pertama blob adalah IV, sisanya ciphertext.

## Recon

```bash
file challenge.flac
ffprobe -v error -show_format -show_streams challenge.flac
metaflac --list challenge.flac
strings -a -n 6 challenge.flac | head
```

Hasil penting:

```text
FLAC audio bitstream data, 16 bit, mono, 44.1 kHz, 352800 samples
duration=8.000000
```

Komentar Vorbis memberi arah analisis:

```text
Phase 1 Complete. Tuned strictly to the notes.
(Format your findings with hyphens, and secure them with a 256-bit hash)
We analyzed a 16K sample block...
```

Petunjuk tersebut mengarah ke tiga hal:

- identifikasi nada atau akor,
- gabungkan hasil memakai tanda hubung,
- hash menggunakan SHA-256,
- periksa fase pada blok 16K sampel.

## Identifikasi progresi akor

Audio dibagi menjadi empat segmen, masing-masing berdurasi dua detik. FFT pada tiap segmen menunjukkan pitch class dominan berikut:

| Segmen | Nada dominan | Akor |
|---|---|---|
| 0–2 detik | A, C, E | A minor (`Am`) |
| 2–4 detik | C, E, G | C major (`C`) |
| 4–6 detik | F, A, C | F major (`F`) |
| 6–8 detik | G, B, D | G major (`G`) |

Progresinya adalah:

```text
Am-C-F-G
```

Material kuncinya mengikuti komentar metadata:

```python
key = sha256(b"Am-C-F-G").digest()
```

Hash yang dihasilkan:

```text
cb527e852c952db127257cace1262443d0cd493f4a253566578f660ff89dae11
```

## Ekstraksi phase coding

Ambil tepat 16.384 sampel pertama dan jalankan FFT tanpa window:

```python
spectrum = np.fft.fft(samples[:16384])
phases = np.angle(spectrum)
```

Bin DC dilewati. Fase bin berikutnya berada di sekitar `+π/2` atau `-π/2`, sehingga tandanya dapat dipetakan menjadi bit:

```python
bits = (phases[1:] < 0).astype(np.uint8)
```

Pemetaan yang dipakai:

```text
fase positif -> 0
fase negatif -> 1
```

Empat byte pertama dibaca sebagai integer big-endian:

```text
00 00 02 00 -> 512 bit
```

Setelah header 32 bit, 512 bit berikutnya membentuk blob 64 byte:

```text
09532f957c765ca1eb5fcd25d50d742a
3a2570e98a31814cb6c92ccaea72652b
f7348a48401cdb5e211728b7a797d3a5
d9243f34c96d4dc92d0512ffb7eda4a0
```

## Dekripsi

Struktur blob:

```text
16 byte IV || 48 byte AES-CBC ciphertext
```

Dekripsi dilakukan dengan AES-256-CBC memakai hasil SHA-256 progresi akor. Plaintext memakai PKCS#7 padding.

```python
iv = payload[:16]
ciphertext = payload[16:]
key = hashlib.sha256(b"Am-C-F-G").digest()
```

Setelah dekripsi dan unpadding:

```text
TBCTF{Ph4s3_M0dul4t10n_1s_Tr1cky_!992}
```

## Menjalankan solver

```bash
python3 solve.py challenge.flac
```

Output:

```text
[*] sample rate : 44100 Hz
[*] samples     : 352800
[*] progression : Am -> C -> F -> G
[*] key material: Am-C-F-G
[*] SHA-256 key : cb527e852c952db127257cace1262443d0cd493f4a253566578f660ff89dae11
[*] phase data  : 512 bits (64 bytes)
[+] flag        : TBCTF{Ph4s3_M0dul4t10n_1s_Tr1cky_!992}
```

## Flag

```text
TBCTF{Ph4s3_M0dul4t10n_1s_Tr1cky_!992}
```

# Transmission

## Ringkasan

Archive berisi satu file `unknown.unknown`, tetapi entry ZIP terenkripsi. Password tidak ada sebagai string plain di dalam archive, sehingga layer pertama diselesaikan dengan cracking lokal terhadap ZipCrypto.

Password yang valid adalah:

```text
whatever1
```

Setelah diekstrak, `unknown.unknown` ternyata merupakan file WAV PCM 16-bit mono 44100 Hz berdurasi 6 detik. Pesan tidak tersimpan sebagai teks pada metadata atau raw string, tetapi digambar pada domain frekuensi. Saat audio dibuka sebagai spectrogram/waterfall, flag terlihat jelas.

## File Challenge

```bash
$ file Transmission.zip
Transmission.zip: Zip archive data, made by v3.0 UNIX, extract using at least v2.0

$ zipinfo -v Transmission.zip
unknown.unknown
compression method: deflated
file security status: encrypted
CRC: dfd0c27e
uncompressed size: 529244
```

## Analisis Awal

`unzip -l` hanya menampilkan satu entry:

```text
unknown.unknown
```

Saat diekstrak biasa, `unzip` meminta password. Dari `zipinfo -v`, flag bit menunjukkan bahwa entry menggunakan enkripsi ZIP klasik/ZipCrypto, bukan AES.

## Layer ZIP

Cracking dilakukan secara lokal menggunakan kandidat wordlist dan mutasi sederhana. Password yang cocok adalah:

```text
whatever1
```

Ekstraksi dilakukan dengan:

```bash
unzip -P whatever1 Transmission.zip
```

Hasilnya:

```bash
$ file unknown.unknown
unknown.unknown: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 44100 Hz
```

## Layer Audio

File WAV memiliki durasi sekitar 6 detik. Pemeriksaan menggunakan `strings` pada raw audio tidak menghasilkan flag, sehingga payload bukan berupa teks langsung.

Karena challenge menggunakan konsep *transmission* dan *signal*, file kemudian dianalisis menggunakan waterfall/spectrogram.

Command yang digunakan:

```bash
sox unknown.unknown -n spectrogram -o spectrogram.png -x 3000 -y 1000 -z 60 -r -m -l -t Transmission
```

Pada `spectrogram.png`, teks flag terlihat jelas di bagian tengah:

```text
0xV01D{h1dd3n_1n_th3_sp3ctr0}
```

## Penyusunan Solve Script

`solve.py` melakukan dua tahap:

1. Mengekstrak `unknown.unknown` dari `Transmission.zip` menggunakan password `whatever1`.
2. Membuat `spectrogram.png` menggunakan SoX agar flag dapat diverifikasi secara visual.

Script juga mencetak flag yang terbaca dari spectrogram.

## Cara Menjalankan

```bash
python3 solve.py
```

Output yang diharapkan:

```text
[+] extracted: unknown.unknown
[+] spectrogram: spectrogram.png
<FLAG>0xV01D{h1dd3n_1n_th3_sp3ctr0}</FLAG>
```

## Flag

```text
0xV01D{h1dd3n_1n_th3_sp3ctr0}
```

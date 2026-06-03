# Woɹsǝ - Forensic Writeup

## Informasi Challenge

- **Judul:** Woɹsǝ
- **Kategori:** Forensic
- **Deskripsi:** `It will be Woɹsǝ, if you read it wrong...`
- **File:** `chal.wav`

## Recon Awal

File yang diberikan adalah audio WAV:

```bash
file chal.wav
```

Output:

```text
chal.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 8 bit, mono 8000 Hz
```

Metadata dengan `exiftool` menunjukkan bahwa audio berdurasi sekitar 19.53 detik, mono, sample rate 8000 Hz, dan 8-bit PCM.

```bash
exiftool chal.wav
```

Bagian penting:

```text
File Type              : WAV
Encoding               : Microsoft PCM
Num Channels           : 1
Sample Rate            : 8000
Bits Per Sample        : 8
Duration               : 19.53 s
```

## Analisis Spectrogram

Saat audio dibuka dan dilihat melalui spectrogram, terlihat adanya teks/pola tersembunyi yang mengarah ke URL Pastebin:

```text
https://pastebin.com/raw/QDANJxiQ
```

Namun isi Pastebin tersebut membutuhkan password.

## Analisis Audio Morse

Hint pada judul challenge adalah `Woɹsǝ`, yaitu bentuk terbalik dari `Worse`. Ini memberi petunjuk bahwa pembacaan bisa salah jika arah/pola audio tidak diperhatikan.

Audio `chal.wav` ternyata berisi sinyal Morse. Setelah didecode beberapa kali dan dikoreksi dari hasil decoder yang kurang akurat, pesan Morse mengarah ke password:

```text
THEM?!ONTOP
```

Password ini digunakan untuk membuka konten Pastebin.

## Flag

Setelah password `THEM?!ONTOP` digunakan, flag berhasil ditemukan:

```text
THEM?!CTF{1F_Y0U_F0UND_TH1S_S4Y_TH3M?!_0N_T0P_13298}
```

## Kesimpulan

Challenge ini menggabungkan dua teknik forensic audio:

1. **Spectrogram analysis** untuk menemukan URL Pastebin tersembunyi.
2. **Morse code decoding** dari audio untuk mendapatkan password Pastebin.

Judul `Woɹsǝ` menjadi clue bahwa decoding bisa keliru jika sinyal dibaca dengan cara yang salah. Setelah pesan Morse dikoreksi, password valid adalah `THEM?!ONTOP`, yang membuka Pastebin dan menghasilkan flag final.

# Thanh Hoa 2 — Forensics Writeup

**CTF:** LYKNCTF 2026  
**Category:** Forensics  
**Challenge:** Thanh Hoa 2  
**Description:** `36 Thanh Hoa`  
**Flag:** `LYKNCTF{NGU01_TH4NH_H04_4N_R4U_M4_PH4_DU0NG_T4U}`

## Ringkasan

File `lyknctf(2).mp4` punya ZIP AES yang ditempel di akhir file. Arsip tersebut berisi `flag.txt`, tetapi butuh password.

Petunjuk password disimpan pada audio. Audio challenge kedua sangat mirip dengan video `Thanh Hoa` sebelumnya, tetapi memiliki lapisan tambahan. Setelah kedua audio disamakan skalanya lalu dikurangkan, spektrogram residual menampilkan tulisan:

```text
RAUMAPHATAU RAUMAPHATAU RAUMAPHATAU ...
```

Password `RAUMAPHATAU` membuka ZIP dan menghasilkan flag.

## 1. Triage MP4

Cek tipe file dan stream media:

```bash
file 'lyknctf(2).mp4'
ffprobe -v error -show_format -show_streams 'lyknctf(2).mp4'
```

Hasil utamanya:

```text
ISO Media, MP4 Base Media v1
Video : H.264, 1280x720
Audio : AAC, stereo, 44100 Hz
Durasi: sekitar 386.94 detik
```

Cari string dan signature arsip:

```bash
strings -a -t d 'lyknctf(2).mp4' | grep -E 'flag\.txt|PK'
```

`flag.txt` muncul di bagian paling akhir file. Pencarian signature ZIP memberi offset:

```bash
python3 - <<'PY'
from pathlib import Path

data = Path('lyknctf(2).mp4').read_bytes()
print(data.rfind(b'PK\x03\x04'))
PY
```

Output:

```text
31910541
```

Artinya ZIP ditempel mulai offset `31910541` sampai EOF.

## 2. Carve ZIP

```bash
dd if='lyknctf(2).mp4' of=hidden.zip bs=1 skip=31910541 status=none
file hidden.zip
unzip -l hidden.zip
```

Isi arsip:

```text
Archive: hidden.zip
  Length      Name
---------     --------
       49     flag.txt
```

`zipinfo -v` menunjukkan compression method `99` dan extra field `0x9901`, ciri WinZip AES. Jadi `flag.txt` belum bisa dibaca tanpa password.

## 3. Bandingkan audio dengan challenge sebelumnya

Video kedua punya durasi dan isi visual yang sama dengan file `lyknctf.mp4` dari challenge sebelumnya. Perbedaannya paling terasa pada bitrate audio:

```text
Thanh Hoa 1: sekitar 128 kbps
Thanh Hoa 2: sekitar 197 kbps
```

Ekstrak kedua audio sebagai PCM dengan sample rate dan channel yang sama:

```bash
ffmpeg -v error -i lyknctf.mp4 -vn -ac 2 -ar 44100 old_audio.wav
ffmpeg -v error -i 'lyknctf(2).mp4' -vn -ac 2 -ar 44100 new_audio.wav
```

Kalau langsung dibuat spektrogram, tulisan masih tertutup musik. Solusinya adalah mengurangi sinyal lama dari sinyal baru.

Skala optimal dihitung dengan least squares:

```text
alpha = dot(old, new) / dot(old, old)
residual = new - alpha * old
```

Kode untuk membuat spektrogram residual 60 detik pertama:

```python
import numpy as np
import matplotlib.pyplot as plt
from scipy.io import wavfile
from scipy.signal import stft

sr_old, old = wavfile.read('old_audio.wav')
sr_new, new = wavfile.read('new_audio.wav')
assert sr_old == sr_new == 44100

# Ambil mono dan batasi 60 detik pertama.
limit = 60 * sr_new
old = old[:limit].astype(np.float32).mean(axis=1)
new = new[:limit].astype(np.float32).mean(axis=1)

alpha = np.dot(old, new) / np.dot(old, old)
residual = new - alpha * old

freq, time, spectrum = stft(
    residual,
    fs=sr_new,
    nperseg=2048,
    noverlap=1536,
    boundary=None,
)

db = 20 * np.log10(np.abs(spectrum) + 1)
plt.figure(figsize=(16, 6))
plt.pcolormesh(time, freq, db, shading='auto')
plt.ylim(0, 22050)
plt.xlabel('Time (s)')
plt.ylabel('Frequency (Hz)')
plt.tight_layout()
plt.savefig('spectrogram-residual.png', dpi=160)
```

Pada rentang sekitar 6–12 kHz terlihat teks besar yang diulang:

```text
RAUMAPHATAU
```

Ini juga cocok dengan stereotip/ungkapan Thanh Hóa tentang `rau má phá tàu`, sehingga bukan string acak.

## 4. Buka ZIP

Gunakan tulisan dari spektrogram sebagai password:

```bash
7z x hidden.zip -pRAUMAPHATAU
cat flag.txt
```

Output:

```text
LYKNCTF{NGU01_TH4NH_H04_4N_R4U_M4_PH4_DU0NG_T4U}
```

## 5. Solver final

`solve.py` melakukan langkah yang dibutuhkan setelah password ditemukan:

1. Mencari local header ZIP terakhir di MP4.
2. Mengambil seluruh data dari offset ZIP sampai EOF.
3. Mendekripsi WinZip AES dengan password `RAUMAPHATAU`.
4. Mendekompresi `flag.txt`.
5. Mencetak flag.

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py 'lyknctf(2).mp4'
```

Output:

```text
[+] ZIP offset : 31910541
[+] Password   : RAUMAPHATAU
[+] Extracted  : flag.txt
<FLAG>LYKNCTF{NGU01_TH4NH_H04_4N_R4U_M4_PH4_DU0NG_T4U}</FLAG>
```

## Flag

```text
LYKNCTF{NGU01_TH4NH_H04_4N_R4U_M4_PH4_DU0NG_T4U}
```

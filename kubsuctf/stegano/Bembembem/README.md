# Writeup Challenge: bembembem (Misc)

## Deskripsi
Challenge ini melibatkan analisis file video `bembembem.mp4` yang berisi data tersembunyi baik dalam bentuk metadata, audio, maupun lampiran di akhir file (file tail).

## Langkah-langkah Penyelesaian

### 1. Enumerasi Awal dan Metadata
Langkah pertama adalah memeriksa metadata file menggunakan `exiftool` dan mencari string mencurigakan dengan `strings`.

*   **Metadata Penting**: Ditemukan tag `vid_md5` dengan nilai `6899efc8f52bffb08c5ac45deee24f64`.
*   **Hidden String**: Ditemukan string Base64 panjang yang memiliki komentar `# decode: base64 -> zlib inflate -> utf-8`.
    Setelah didekode, instruksi berikut muncul:
    *   Ada petunjuk tentang menit ke-42 dan frekuensi di atas 10kHz.
    *   Ada data "tail" di akhir file MP4 yang di-XOR menggunakan kunci `vid_md5`.
    *   Data tersebut adalah ZIP (PK) yang dilindungi password hasil dari spektrum audio.

### 2. Ekstraksi dan Dekripsi Data Tersembunyi (Tail)
Data tersembunyi terletak di akhir file MP4, dimulai setelah marker `fs:=`. 

*   **Offset**: Data dimulai pada byte `268469633`.
*   **Proses**: Mengambil sisa byte dari offset tersebut dan melakukan operasi XOR menggunakan kunci `vid_md5` (`6899efc8f52bffb08c5ac45deee24f64`) secara berulang.
*   **Hasil**: Sebuah file ZIP bernama `tail.zip`.

```python
# Snippet script dekripsi
key = "6899efc8f52bffb08c5ac45deee24f64"
with open("bembembem.mp4", "rb") as f:
    f.seek(268469633)
    data = f.read()
decrypted = bytes([data[i] ^ ord(key[i % len(key)]) for i in range(len(data))])
with open("tail.zip", "wb") as f:
    f.write(decrypted)
```

### 3. Analisis Spektrogram Audio
Untuk membuka `tail.zip`, diperlukan password 8 karakter yang disembunyikan dalam spektrogram audio.

*   **Waktu**: Sekitar menit ke-42 (`00:42:00`).
*   **Filter**: Frekuensi di atas 10.000 Hz.
*   **Analisis**: Menggunakan `ffmpeg` atau `sox` untuk menghasilkan spektrogram. Pada frekuensi tinggi di menit tersebut, terlihat teks "bisikan" yang membentuk karakter.
*   **Password**: Karakter yang terlihat adalah `K0t05t`.

### 4. Ekstraksi Flag
Gunakan password `K0t05t` untuk mengekstrak `tail.zip`.

```bash
unzip -P "K0t05t" tail.zip
```

Di dalam ZIP terdapat file `flag.txt` yang berisi flag utama.

## Flag
**KubSTU{3nj0y_1h_0f_M3ll57r0y_m3m3s}**

# Robot rambles

File yang diberikan adalah `rambles.wav`, sebuah WAV PCM 16-bit mono 44.1 kHz dengan durasi sekitar 111 detik. Suaranya terdengar seperti sinyal radio/robot, jadi aku mulai dari mengecek bentuk frekuensinya.

## Langkah analisis

Pertama, file dicek dengan `file` dan `ffprobe`:

```bash
file rambles.wav
ffprobe -hide_banner rambles.wav
```

Hasilnya menunjukkan audio normal, bukan arsip yang disamarkan. Saat dibuat spectrogram, sinyalnya berkutat di rentang sekitar 1200 Hz sampai 2300 Hz. Pola ini cocok dengan SSTV: 1200 Hz biasanya dipakai sebagai sync, sedangkan data gambar dikirim sebagai tone FM di sekitar 1500-2300 Hz.

Di awal audio ada preamble VIS. Dengan membaca tone 30 ms setelah leader:

- 1100 Hz berarti bit `1`
- 1300 Hz berarti bit `0`
- bit dikirim LSB-first

Bit VIS yang terbaca menghasilkan kode desimal `60`. Kode ini mengarah ke mode **Scottie 1**.

## Decode

Aku tidak memakai decoder eksternal. `solve.py` melakukan demodulasi sendiri:

1. Membaca WAV dengan modul `wave`.
2. Mengambil instantaneous frequency memakai Hilbert transform.
3. Membaca VIS code dan memvalidasi bahwa nilainya `60`.
4. Menyusun ulang gambar Scottie 1 ukuran 320x256.
5. Menyimpan hasil ke `decoded_scottie1.png`.

Timing utama Scottie 1 yang dipakai:

- satu komponen warna: 138.24 ms
- separator: 1.5 ms
- sync: 9 ms
- urutan channel yang direkonstruksi: Green, Blue, lalu Red


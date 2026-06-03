# Writeup - Signal Audit (rev)

Challenge ini cuma kasih satu file: `audit.wav`.

## 1) Recon awal

Saya mulai dari cek tipe file dan metadata:

- `file audit.wav` -> WAV PCM 16-bit mono 44.1 kHz
- durasi sekitar 36.9 detik
- tidak ada metadata aneh/embedded yang langsung mengarah ke flag

Karena deskripsi nyebut "rhythmic transmission", "HF bands", "QSL", "73", saya fokus ke analisis sinyal radio, bukan stego file biasa.

## 2) Identifikasi mode transmisi

Saya profiling frekuensi dominan per potongan waktu kecil.

Ditemukan pola khas:

- leader tone 1900 Hz
- break/start tone 1200 Hz
- lalu bit VIS dengan 1100/1300 Hz

Dari decode VIS, code yang muncul adalah **8**, yang sesuai dengan **SSTV Robot36**.

Setelah itu saya cek pulse sinkronisasi per line dan ketemu:

- sync pulse sekitar 1200 Hz
- berulang periodik tiap ~150 ms
- total sekitar 240 line

Ini konsisten dengan mode Robot36.

## 3) Decode gambar SSTV

Saya bikin decoder sendiri di Python:

- hitung instantaneous frequency dari audio (`hilbert`)
- cari timing line awal (`t0`) dengan minimisasi error ke tone sync 1200 Hz
- ambil komponen luminance (Y) per line sesuai timing Robot36:
  - sync 9 ms
  - porch 3 ms
  - Y scan 88 ms
- render jadi `decoded_luma.png`

Dari hasil decode gambar, teks flag terlihat jelas di bagian bawah image.

## 4) Flag

`KSUS{s4n1ty_ch3ck_QSL_7373}`

## 5) Solver

Solver final disimpan di `solve.py`.

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Script juga menyimpan hasil decode grayscale ke `decoded_luma.png` buat verifikasi visual.

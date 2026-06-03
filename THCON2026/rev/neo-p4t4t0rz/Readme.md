## Writeup - neo-p4t4t0rz

Challenge ini sengaja dipasang beberapa jebakan. Jalur awal binary native memang mengarah ke string yang kelihatan seperti flag, dan itu yang bikin saya sempat salah fokus di awal. Setelah dicek ulang ke validator yang benar, string itu cuma decoy.

Flag yang benar:

```text
R3al1ty_D3p3nd5_0n_y0ur_Ch01c3s
```

### 1. Recon awal

File yang diberikan adalah PE x64 Windows:

```text
neo_p4t4t0rz_pwned_you.exe
```

Kalau dilihat cepat dengan `strings`, ada banyak referensi Matrix, ada string yang mirip flag, dan ada flow yang sengaja dibuat dramatis. Karena ini kategori rev, saya mulai dari memetakan jalur eksekusi utama.

Yang langsung keliatan:

1. Ada wrapper native.
2. Wrapper ini melakukan dekripsi payload lain.
3. Ada output yang sengaja terlihat seperti success path.
4. Jalur visual program tidak bisa dipercaya begitu saja.

### 2. Decoy di wrapper native

Di tahap awal saya sempat menemukan string:

```text
W3LC0ME_T0_TH3_R34
```

String ini memang bisa muncul dari jalur inisialisasi wrapper native. Kalau fungsi init diemulasi, buffer global akan berisi blob base64 yang setelah di-decode menghasilkan string model `Thcon{...}`. Sekilas kelihatan seperti jawaban final.

Masalahnya: saat kandidat ini diuji ke validator login sebenarnya, hasilnya ditolak.

Jadi kesimpulan pentingnya:

- wrapper native memang menyimpan string seperti flag
- tapi itu bukan password recovery yang dipakai jalur validasi utama
- challenge ini punya fake flag yang sengaja dipasang untuk menjebak solver yang berhenti terlalu cepat

### 3. Ambil payload stage-2

Wrapper native ternyata menyimpan payload .NET terenkripsi di dalam binary. Payload itu didekripsi dengan XOR stream hasil LCG, lalu menghasilkan PE managed yang valid.

Intinya:

1. ambil blob terenkripsi dari binary
2. bangun keystream 32 byte
3. XOR seluruh blob
4. hasilnya file .NET stage-2

Setelah payload stage-2 dibuka, baru flow validasi aslinya mulai masuk akal.

### 4. Validasi utama ternyata ada di payload .NET

Di assembly managed, entry point login akhirnya mengarah ke:

```text
NethereumVM.PayloadEncoder::EncodePayload(string)
```

Bukan ke string decoy dari wrapper.

Beberapa temuan penting:

1. Input harus panjang 31 byte UTF-8.
2. Ada fungsi `GenerateChecksum()`.
3. Checksum ini dipakai oleh `SignalProcessor.DecryptBlock(...)`.
4. `DecryptBlock` membangun `DynamicMethod` besar yang menjadi validator real.

Jadi flag bukan dibandingkan langsung terhadap string plaintext. Yang dicek adalah hasil eksekusi validator dinamis yang dibangkitkan dari checksum internal.

### 5. Kenapa reversing-nya nyebelin

Bagian paling mengganggu di challenge ini adalah validatornya tidak hadir sebagai fungsi IL biasa yang enak dibaca. Dia dibuat runtime sebagai `DynamicMethod`.

Artinya:

1. kita tidak cukup hanya decompile assembly
2. kita harus menangkap method dinamis yang sudah jadi
3. lalu mendisasm atau menginterpretasi IL hasil generate itu

Selain itu ada beberapa probe anti-analysis / anti-debug yang mempengaruhi checksum pembentuk validator. Jadi kalau asumsi environment salah, validator yang dihasilkan juga bisa salah.

### 6. Cara saya menembus validator dinamis

Strategi yang paling efektif akhirnya begini:

1. patch assembly supaya `DynamicMethod` hasil `DecryptBlock` bisa disimpan sebelum didelegasikan
2. dump bytecode IL yang sudah terbangun
3. interpretasi IL itu secara terkontrol
4. pecah constraint per posisi karakter input
5. uji kandidat yang tersisa

Setelah IL dinamis berhasil dibaca, kelihatan bahwa validator memproses byte input dalam urutan yang diacak. Setiap segmen memaksakan syarat tertentu ke satu posisi karakter. Dari situ ruang pencarian turun drastis.

Hasil solving memberi beberapa kandidat dekat, misalnya versi yang memakai huruf mirip angka, tapi setelah diverifikasi ulang ke jalur validasi yang benar, hanya satu yang konsisten.

### 7. Flag final

Flag yang benar adalah:

```text
R3al1ty_D3p3nd5_0n_y0ur_Ch01c3s
```

Kalimat ini juga masuk akal dengan tema Matrix, dan lebih penting lagi, ini satu-satunya hasil yang lolos validasi real, bukan fake path.

### 8. Catatan penting

Pelajaran dari challenge ini lumayan jelas:

1. jangan berhenti di string yang “terlihat benar”
2. kalau ada multi-stage payload, validasi stage terakhir yang harus dipercaya
3. kalau ada `DynamicMethod`, kemungkinan besar inti challenge ada di sana
4. output UI, pesan sukses, bahkan string yang formatnya pas, belum tentu flag final

### 9. Solver

`solve.py` di folder ini sudah diarahkan ke flag final yang tervalidasi:

```text
R3al1ty_D3p3nd5_0n_y0ur_Ch01c3s
```

Saya sengaja tidak mempertahankan solver decoy lama karena itu justru menghasilkan fake flag dari wrapper native.

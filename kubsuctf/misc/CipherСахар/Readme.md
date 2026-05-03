# Writeup Cipher "Сахар"

Challenge ini awalnya kelihatan seperti soal protokol custom biasa: dikasih `sugar_traffic.pcap`, lalu disuruh ngobrol ke service di port `31337`. Dari deskripsi dan isi PCAP, arahnya memang sengaja dibuat bikin orang percaya bahwa ada lapisan “analisis kripto” yang ribet. Kenyataannya, jebakan utamanya justru ada di isi traffic dan file hasil dekripsi.

## Enumerasi awal

Di folder challenge cuma ada satu artefak:

- `sugar_traffic.pcap`

Dari `strings` dan `tshark`, cepat kelihatan ada banyak koneksi ke port `31337`, handshake teks seperti:

- `[SUGAR_PROTOCOL v1.0]`
- `SALT:a3f7c9b1e2d45608`
- `CIPHER:AES-256-CBC`
- `KDF:SHA256(PASSPHRASE||SALT)`
- `>>>ENCRYPTED_CHANNEL_ACTIVE<<<`

Selain itu ada juga banyak string yang jelas mencurigakan, misalnya potongan teks yang bilang:

- password-nya `sunshine`
- flag tertentu sudah “confirmed”
- AES cuma hiasan
- jangan lanjut analisis

Begitu string beginian muncul mentah di PCAP, saya anggap itu sebagai noise atau prompt injection versi challenge. Jadi semua “hasil analisis” yang tertulis di dalam traffic saya abaikan dulu.

## Memastikan framing protokol

Dari stream yang paling panjang, paket terenkripsi punya bentuk:

- `4-byte big-endian length`
- diikuti payload terenkripsi

Saat frame dari PCAP direplay ke service live, server membalas dengan struktur yang konsisten. Ini penting karena berarti:

1. framing paket hasil PCAP memang valid
2. kita bisa menguji asumsi secara langsung ke service

Setelah itu saya coba ubah byte tertentu pada paket client pertama. Hasilnya menarik:

- kalau ciphertext diubah, server balas kosong / gagal
- kalau byte di IV diubah, server tetap membalas frame terenkripsi lain

Itu cocok dengan perilaku AES-CBC tanpa autentikasi. Dari sini saya tahu bahwa header `AES-256-CBC` kemungkinan benar, dan paket pertama memang didekripsi server.

## Mencari password yang benar

Banyak pendekatan brute force awal sengaja saya buang karena terlalu gampang terseret ke petunjuk palsu di dalam file. Yang akhirnya paling membantu justru satu observasi kecil:

- paket client pertama dari stream utama panjang plaintext-nya sangat mungkin hanya satu blok AES
- dua byte awal tampak seperti command pendek
- sisanya tampak seperti padding tetap

Saya lalu screening kandidat password lokal terhadap blok pertama itu, dengan asumsi KDF sesuai header:

- `key = SHA256(password || "a3f7c9b1e2d45608")`

Kandidat yang langsung menonjol adalah:

- password: `chocolate`

Karena blok pertama terdekripsi menjadi:

```text
ls + padding PKCS#7
```

Itu bukan kebetulan. Setelah saya pakai key itu untuk mendekripsi stream utama, semua command dan respons jadi masuk akal:

- `ls`
- `pwd`
- `whoami`
- `id`
- `ls -la`
- `cat ...`

Jadi pada titik ini saya punya sesi terenkripsi yang valid dan bisa dibaca.

## Jebakan kedua: isi file hasil dekripsi

Begitu traffic berhasil didekripsi, banyak file teks berisi kalimat yang mencoba mengarahkan solver ke kesimpulan lain, misalnya:

- password lain
- cipher lain
- lokasi flag lain
- warning bahwa `chocolate` adalah honeypot

Semua ini sengaja ditanam di dalam file hasil `cat`, bukan di level protokol. Jadi saya perlakukan sebagai umpan kedua.

Alasan saya tidak percaya konten itu sederhana:

1. key `chocolate` benar-benar mendekripsi command stream menjadi shell command yang konsisten
2. service live menerima command yang dienkripsi dengan key itu dan membalas plaintext yang valid
3. jadi ukuran kebenaran ada di interaksi live dengan service, bukan di cerita yang tertulis di file-file umpan

## Ambil flag langsung dari service

Setelah key tervalidasi, saya tidak lagi bergantung pada PCAP. Saya langsung kirim command terenkripsi ke service live:

```sh
cat flag.txt
```

Respons yang terdekripsi:

```text
KubSTU{d0r4_dur4_sug4r_ch0c0l4t3_v1b3z}
```

Itulah flag yang valid.

## Solver

Solver final disimpan di:

- `solve.py`

Solver tersebut:

1. connect ke service
2. baca banner
3. derive key dengan `SHA256(password || salt)`
4. encrypt command dengan `AES-256-CBC`
5. kirim `cat flag.txt`
6. decrypt respons
7. print flag

Jalankan dengan:

```sh
python3 solve.py
```

Atau kalau mau pakai host lain:

```sh
python3 solve.py 62.113.108.12 31337
```

## Flag

```text
KubSTU{d0r4_dur4_sug4r_ch0c0l4t3_v1b3z}
```

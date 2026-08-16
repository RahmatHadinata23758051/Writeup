# Diabolical — scriptCTF REV Writeup

## TL;DR

The binary contains a scary crypto validator, but that path is a decoy. The actual flag is stored in `.rodata` as Base64:

    c2NyaXB0Q1RGe24wdF9zMF9oNHJkXzRmdDNyXzRsbH0=

Decoding it gives:

    scriptCTF{n0t_s0_h4rd_4ft3r_4ll}

---

## 1. Initial Analysis

Pertama identifikasi binary:

    file vault

Hasil:

    ELF 64-bit LSB executable, x86-64, statically linked, stripped

Binary merupakan executable Go yang sudah di-strip dan menggunakan static linking.

Ketika dijalankan, program menampilkan prompt:

    key>

Jika diberikan input biasa, input akan ditolak setelah muncul spinner singkat.

---

## 2. Analisis Jalur Crypto

Setelah melakukan reverse engineering terhadap validator utama, terlihat bahwa program melakukan proses kriptografi yang cukup kompleks.

Program membangun target plaintext menggunakan AES-GCM, kemudian melakukan perbandingan terhadap hasil:

    SHA256(HMAC_SHA256(user_input || derived_length_byte))

Hasil tersebut dibandingkan dengan:

    SHA256(target_96_bytes)

Sekilas hal ini terlihat seperti jalur utama untuk mendapatkan flag.

Namun terdapat masalah penting.

Output HMAC-SHA256 memiliki panjang tetap:

    32 bytes

Sedangkan target plaintext memiliki panjang:

    96 bytes

Artinya, untuk mendapatkan input yang menghasilkan target tersebut diperlukan preimage/second-preimage terhadap SHA-256 yang secara praktis tidak feasible.

Dengan demikian, jalur crypto tersebut sangat kemungkinan merupakan **decoy**.

---

## 3. Mencari Data Tersembunyi

Daripada mencoba memecahkan validator crypto, langkah berikutnya adalah memeriksa data statis yang terdapat di dalam binary.

Karena binary Go statically linked, output `strings` cukup ramai oleh string dari Go runtime.

Gunakan pencarian terhadap string Base64 yang mencurigakan:

    strings -a -n 16 vault | grep 'c2NyaXB0Q1RG'

Ditemukan:

    c2NyaXB0Q1RGe24wdF9zMF9oNHJkXzRmdDNyXzRsbH0=

String tersebut terlihat seperti Base64 karena hanya menggunakan karakter yang valid untuk encoding Base64 dan memiliki padding `=` di akhir.

---

## 4. Decode Base64

Decode string tersebut:

    echo 'c2NyaXB0Q1RGe24wdF9zMF9oNHJkXzRmdDNyXzRsbH0=' | base64 -d

Hasil:

    scriptCTF{n0t_s0_h4rd_4ft3r_4ll}

Flag langsung ditemukan tanpa perlu memecahkan crypto validator.

---

## 5. Solver

Solver dapat dibuat sederhana dengan mencari string Base64 yang memiliki prefix `c2NyaXB0Q1R`.

Contoh penggunaan:

    python3 solve.py ./vault

Solver melakukan langkah:

1. Membaca binary.
2. Mencari string ASCII yang kemungkinan merupakan Base64.
3. Decode setiap kandidat.
4. Mencari pola flag `scriptCTF{...}` pada hasil decode.
5. Menampilkan flag ketika ditemukan.

Output:

    FLAG: scriptCTF{n0t_s0_h4rd_4ft3r_4ll}

---

## 6. Kesimpulan

Challenge ini sengaja membuat validator terlihat jauh lebih sulit dengan memasukkan proses kriptografi yang kompleks.

Jalur yang terlihat:

    User Input
        ↓
    HMAC-SHA256
        ↓
    SHA256
        ↓
    AES-GCM
        ↓
    Validation

Namun jalur tersebut merupakan decoy.

Jalur sebenarnya jauh lebih sederhana:

    Binary
        ↓
    strings
        ↓
    Base64 blob
        ↓
    Base64 decode
        ↓
    Flag

Intinya, sebelum mencoba memecahkan crypto yang terlihat rumit, selalu lakukan pemeriksaan terhadap data statis yang tertanam di binary.

---

## Flag

    scriptCTF{n0t_s0_h4rd_4ft3r_4ll}

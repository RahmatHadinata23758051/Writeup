# scriptCTF REV — F**K / `funk`

## Ringkasan

Challenge memberikan file bernama `funk`. Walaupun kategorinya Reverse Engineering, file ini bukan ELF/executable native, melainkan program **Brainfuck** satu baris.

Flag akhir:

    scriptCTF{t1mm1ng_s1d$_ch@nn31}

---

## 1. Identifikasi Awal

Perintah awal:

    file funk
    wc -c funk
    head -c 100 funk

Hasil penting:

    funk: ASCII text, with very long lines
    28786 funk
    ,>,>,>,>>><<<>,>>>>>>>>...

Karakter yang muncul hanya berupa instruksi Brainfuck seperti:

    + - < > [ ] . ,

Jadi pendekatan normal seperti `strings`, `readelf`, atau `objdump` tidak relevan.

File perlu dianalisis sebagai program Brainfuck.

---

## 2. Analisis Program

Program menggunakan instruksi `,` untuk membaca input.

Saat diinterpretasikan, program hanya benar-benar mengonsumsi 31 byte input sebelum masuk ke jebakan loop pada bagian akhir.

Bagian akhir program berisi loop kosong/infinite loop. Artinya validasi tidak ditunjukkan melalui output secara langsung, tetapi melalui efek samping eksekusi.

Observasi penting:

- Tidak ada output flag secara langsung.
- Program membaca input kandidat flag.
- Untuk karakter yang benar, jumlah instruksi Brainfuck yang dieksekusi lebih sedikit.
- Untuk karakter yang salah, terdapat loop pembersihan seperti `[-]` yang berjalan lebih lama.

Hal ini menunjukkan bahwa challenge menggunakan **timing side-channel** atau **step-count side-channel**.

---

## 3. Strategi Solve

Daripada mengandalkan waktu eksekusi asli yang dapat dipengaruhi oleh noise sistem, dibuat interpreter Brainfuck lokal untuk menghitung jumlah instruksi yang dieksekusi.

Langkah solver:

1. Parse program Brainfuck.
2. Compress operasi berulang seperti `+++++` dan `>>>>` agar eksekusi lebih cepat.
3. Build jump table untuk pasangan `[` dan `]`.
4. Jalankan program dengan input dummy untuk mengetahui panjang input yang dikonsumsi.
5. Untuk setiap posisi flag:
   - coba semua karakter printable ASCII;
   - jalankan interpreter;
   - hitung jumlah instruksi sebelum final infinite loop;
   - pilih karakter dengan jumlah instruksi paling kecil.

Karena biaya eksekusi per posisi dapat dibedakan, karakter dengan **step count minimum** merupakan karakter flag yang benar.

---

## 4. Solver

Jalankan:

    python3 solve.py ./funk

Output:

    FLAG: scriptCTF{t1mm1ng_s1d$_ch@nn31}

---

## 5. Catatan Flag

Perhatikan bahwa karakter setelah `s1d` adalah **dollar sign (`$`)**:

    s1d$_ch@nn31

Bukan:

    s1d3_ch@nn31

Jadi flag yang valid adalah:

    scriptCTF{t1mm1ng_s1d$_ch@nn31}

---

## Flag

    scriptCTF{t1mm1ng_s1d$_ch@nn31}

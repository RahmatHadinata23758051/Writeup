# Old Cassette Writeup

Challenge ini hanya memberi satu file, `main.bin`. Dari byte awal terlihat pola instruksi seperti `00 e0`, `12 80`, `6x kk`, `8xy4`, dan `dxy5`. Itu cocok dengan ROM CHIP-8, bukan ELF atau format audio biasa.

Entry point ROM berada di `0x200` dan langsung jump ke `0x280`, lalu ke routine utama di `0x900`. Routine utama menggambar teks ke layar CHIP-8. Karakter tidak disimpan langsung sebagai string, tetapi dihitung dari state dua register, `VA` dan `VB`.

Bagian penting:

- `0x2c0` adalah PRNG/state update.
- `0x282` menjalankan PRNG sebanyak counter 32-bit dari `V9:VC:VD:VE`.
- `0x2ac` adalah delay besar: menjalankan `0xffffffff` step sebanyak `0xff` kali.
- Setelah PRNG maju, ROM memilih salah satu tabel data berdasarkan `VA & 7`, mengambil byte pada offset tertentu, lalu menghitung karakter dengan `byte ^ VA ^ VB`.
- Karakter hasilnya disimpan di `V9` dan digambar oleh dispatcher font di `0xdd2`.

Awalnya emulator CHIP-8 sederhana sudah menampilkan prefix `THEM?!CTF`, tetapi eksekusi mentah menjadi lambat saat masuk delay besar. Karena state PRNG hanya 16-bit (`VA` dan `VB`), saya fast-forward dengan cycle detection. Dari sana seluruh karakter bisa diekstrak langsung tanpa render layar.

Hasil akhirnya:

```text
THEM?!CTF{0LD_T4P3_N3V3R_D1E5K7}
```

Script final ada di `solve.py` dan menghasilkan flag yang sama saat dijalankan.

Writeup Cat in the ... Box? - boroCTF (Reverse Engineering)

Tantangan ini menyembunyikan flag di luar ekosistem binary lokal (out-of-band binary execution) dengan memanfaatkan server hosting pihak ketiga dan sengaja memicu fake segmentation fault untuk menipu proses analisis dinamis.

Analisis Binary

Binary dikompilasi dalam keadaan stripped (tanpa informasi simbol debugging). Melalui analisis statis terhadap daftar string unik di memori .rodata, kita dapat mengidentifikasi pola perintah eksekusi CLI berikut:

curl -s -o "%s" "%s%s%s"


Program menggunakan fungsi internal bernama sym.connect. Alih-alih melakukan network handshaking soket standar, fungsi ini diubah (override) untuk mendekripsi sebuah alamat URL secara dinamis menggunakan algoritma XOR.

Pengungkapan Kunci Enkripsi (Known Plaintext Attack)

Di dalam fungsi sym.connect(), terdapat sebuah loop memori yang memproses data terenkripsi sepanjang 24-byte pada alamat 0x00002010. Karena kita mengetahui format string URL hampir pasti diawali oleh skema http:// atau https://, kita melakukan operasi XOR inversi pada 7 byte pertama data tersebut:

$$\text{Data Mentah Memori} \ \oplus \ \text{"http://"} = \text{"ymwe0vy"}$$

Hasil KPA merujuk pada sebuah string statis 6 karakter di memori .rodata yaitu ymweyc. Teks ini merupakan kunci (key) sekaligus masukan teks valid yang diminta oleh program saat pertama kali dijalankan.

Jika kita mendekripsi seluruh data 24-byte di alamat 0x00002010 dengan kunci ymweyc, kita mendapatkan basis domain:

[https://files.catbox.moe/](https://files.catbox.moe/)


Komponen URL berikutnya dibentuk dari input string kunci itu sendiri (ymweyc) yang diakhiri oleh ekstensi .txt. Sehingga jalur file unduhan yang dituju oleh instruksi curl program adalah https://files.catbox.moe/ymweyc.txt.

Langkah Eksploitasi

Binary lokal sengaja ditanami instruksi fault buatan agar memicu crash (Segmentation fault) sesaat setelah membaca input untuk menghentikan investigasi pelaku reverse engineering. Kita dapat melewati batasan binary ini dengan langsung mengunduh file flag dari server Catbox menggunakan curl atau Python script.

Mengambil Flag Secara Langsung

curl -s [https://files.catbox.moe/ymweyc.txt](https://files.catbox.moe/ymweyc.txt)


Hasil Flag

boroCTF{lEts_gO_B3y0nd_b1nar1e$}

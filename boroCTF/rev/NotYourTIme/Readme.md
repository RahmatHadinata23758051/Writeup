Writeup Not Your Time - boroCTF (Reverse Engineering)

Tantangan ini menguji pemahaman dasar mengenai operasi bitwise tingkat rendah di dalam arsitektur x86_64, khususnya penggunaan instruksi not.

Analisis Binary

Saat kita membedah isi fungsi main() menggunakan reverse engineering tool (radare2/Ghidra), kita dapat melihat inisialisasi deretan instruksi pemindahan nilai (data movement) berturut-turut ke dalam memori lokal stack (rbp - offset):

mov dword [var_a0h], 0x9d
mov dword [var_9ch], 0x90
mov dword [var_98h], 0x8d
...


Setelah program menerima input string sepanjang maksimal 25 karakter lewat fungsi scanf("%25s"), program akan masuk ke dalam struktur perulangan loop untuk melakukan komparasi data per karakter:

0x000012f5      mov eax, dword [rbp + rax*4 - 0xa0]  ; Mengambil nilai byte terenkripsi
0x000012fc      f7d0                                 ; Eksploitasi utama: Instruksi NOT (~eax)
0x000012fe      0fb6c0                               ; Konversi ke format 1 byte (Unsigned Char)
0x00001301      39c2                                 ; Membandingkan hasil NOT dengan input user


Alur matematis komparasi di atas bekerja dengan formula:


$$\text{Karakter Input} = \sim\text{Nilai Encrypted}$$

Langkah Penyelesaian

Kita tidak perlu berinteraksi langsung atau melakukan proses debugging dinamis terhadap binary tersebut. Kita cukup mengekstrak seluruh nilai heksadesimal dari instruksi pembentukan array di stack dan membalikkan operasinya menggunakan script Python.

Urutan byte terenkripsi yang ada pada stack:
0x9d, 0x90, 0x8d, 0x90, 0xbc, 0xab, 0xb9, 0x84, 0xb1, 0xcf, 0x8b, 0xa0, 0x91, 0xb0, 0xd4, 0xa0, 0x8b, 0xb7, 0xcc, 0xa0, 0xb9, 0xb3, 0xbf, 0x98, 0x82

Eksekusi Pembalik Karakter

Jalankan script solve.py untuk mengekstrak dan mendekripsi flag secara instan:

python3 solve.py


Flag

boroCTF{N0t_nO+_tH3_FL@g}

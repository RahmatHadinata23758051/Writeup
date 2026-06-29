CTF Writeup: AI Approve Garbled (Misc / Crypto)

Deskripsi Challenge

Deskripsi: They asked a machine to build an impenetrable vault. It responded with an ocean of noise and a single mathematical trap. The oracle is waiting, but your questions are limited.

Koneksi: nc 13.127.119.28 1339

Limitasi: Maksimal 256 queries.

Ringkasan

Challenge ini memberikan sebuah binary berjenis ELF 64-bit yang mengimplementasikan "AI Security Enhancement Pipeline". Sistem membatasi kita hanya pada 256 queries. Berkat adanya file Dockerfile.participant, kita menyadari bahwa binary ini dapat dijalankan secara lokal dalam mode --interactive.

Kerentanan utama terletak pada penggunaan enkripsi yang sepenuhnya Linear (Affine Transformation) dalam mode ECB (Electronic Codebook). Tidak adanya lapisan non-linear (seperti S-Box pada AES yang menggunakan inversi finite field) membuat kunci enkripsi dan pola permutasi blok dapat diekstraksi hanya dengan Known-Plaintext Attack (KPA) sederhana.

Analisis Teori dan Metodologi

1. Deteksi Mode Operasi (ECB)

Pengujian pertama dilakukan dengan mengirimkan input panjang berupa karakter berulang (41 atau huruf 'A' sebanyak 32 byte). Output ciphertext yang dihasilkan adalah:
0a83371f212d94d0d0476945c33d8067 0a83371f212d94d0d0476945c33d8067 ...

Terlihat bahwa blok 16-byte pertama dan kedua memiliki hasil yang sama persis. Secara teoretis, ini membuktikan bahwa enkripsi menggunakan mode Electronic Codebook (ECB), di mana setiap blok $P_i$ dienkripsi secara independen menjadi $C_i$.

2. Sifat Linear dan "The Mathematical Trap"

Sistem kriptografi modern yang aman membutuhkan komponen Non-Linear (S-Box) berdasarkan Prinsip Shannon tentang Confusion dan Diffusion.
Jika sebuah fungsi enkripsi $E(x)$ bersifat linear, maka ia dapat direpresentasikan sebagai operasi matriks (Affine Cipher):
$$ E(x) = A \cdot x \oplus K $$
dimana $A$ adalah matriks permutasi/transformasi dan $K$ adalah Key.

Dalam fungsi linear $XOR$, elemen identitas adalah $0$. Jika kita memberikan input plaintext bernilai $0$, fungsi tersebut akan menghasilkan kuncinya sendiri:
$$ E(0) = A \cdot 0 \oplus K = K $$
Dengan mengirimkan 16-byte 00, kita berhasil memaksa oracle untuk memuntahkan kunci enkripsi ($K$) secara mentah!

3. Membongkar Permutasi (Affine S-Box)

Setelah kunci ($K$) didapatkan, dekripsi awal menghasilkan teks yang diacak: 4F1A_G{f3nsbf0Lx2_bn__1_t11s8_1slt3l}l_nr411.
Ini menandakan matriks $A$ dari fungsi di atas merupakan sebuah fungsi permutasi transposisi byte.

Untuk memetakannya, kita kembali menggunakan Known-Plaintext Attack. Kita mengirimkan urutan byte berurutan: 000102030405060708090a0b0c0d0e0f. Setelah di-XOR kembali dengan kunci $K$, hasil ciphertext akan menunjukkan posisi ke mana setiap byte berpindah.

Langkah Eksekusi (Walkthrough)

Langkah 1: Mencuri Kunci dari Server

Alih-alih membakar 256 queries untuk melakukan brute-force, kita memanfaatkan sesi koneksi pertama untuk menangkap Encrypted Flag, lalu mengirim payload 00 (sebanyak 32 karakter hex) untuk mengekstrak kunci.

Encrypted Flag Server: 7f84471f...

Payload dikirim: 00000000000000000000000000000000

Key yang bocor: 4bc2765e606cd59191062804827cc126

Langkah 2: Menguraikan Pola Permutasi (Lokal)

Karena permutasi bersifat statis, kita bisa melakukan analisis ini di mesin lokal tanpa koneksi internet. Kita menjalankan program lokal dan memasukkan urutan heksadesimal 00 hingga 0f. Output ini digunakan untuk membuat mapping indeks permutasi.

Langkah 3: Final Decryption Script

Berikut adalah script akhir yang digunakan untuk mengotomasikan dekripsi (XOR) dan transposisi (Unscramble):

import subprocess

# 1. Dapatkan pola permutasi menggunakan oracle lokal
p = subprocess.Popen(['./ai-approved-garbled', '--interactive'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
payload = "".join([f"{i:02x}" for i in range(16)])
out, _ = p.communicate((payload + '\n').encode())

ct_hex = ""
for line in out.decode('utf-8', errors='ignore').split('\n'):
    if 'Ciphertext:' in line:
        ct_hex = line.split('Ciphertext:')[1].strip()[:32]
        break

# Key statis yang didapat dari server
key_hex = "4bc2765e606cd59191062804827cc126"
key_b = bytes.fromhex(key_hex)
ct_b = bytes.fromhex(ct_hex)

# Memetakan posisi asal setiap byte
perm = [ct_b[i] ^ key_b[i] for i in range(16)]

# 2. Dekripsi Encrypted Flag Server
enc_flag_hex = "7f84471f3f2baef7a2685b66e44c8d5e799d14303f33e4cee5371977ba23f05527b645321d008affe3322c00b378f022"
enc_b = bytes.fromhex(enc_flag_hex)

# Reversing XOR
xored = [enc_b[i] ^ key_b[i % 16] for i in range(len(enc_b))]

# Reversing Permutasi (Unscrambling)
flag = [''] * len(enc_b)
for block in range(len(enc_b) // 16):
    for i in range(16):
        orig_pos = perm[i]
        flag[block * 16 + orig_pos] = chr(xored[block * 16 + i])

print(f"FLAG: {''.join(flag)}")


Hasil Akhir

Mengeksekusi langkah-langkah di atas berhasil merestorasi flag dengan sempurna:
FLAG{4ff1n3_sb0x_1n_128_b1t_1s_st1ll_l1n34r}

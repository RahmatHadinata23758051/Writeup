Writeup CTF: CuRvE (Kriptografi)

Kategori: Kriptografi
Konsep: ECDSA, Parameter Injection, Pohlig-Hellman Attack, Weak Key Generation
Flag: v1t{SomeTimeICanNotControlMyHeart}

1. Pendahuluan

Pada challenge ini, kita diberikan sebuah layanan yang mengimplementasikan skema tanda tangan digital ECDSA. Kita dapat menandatangani pesan, memverifikasi tanda tangan, dan yang paling menarik, kita diizinkan untuk mengubah parameter kurva eliptik (koefisien $a$ dan $b$). Tujuan akhirnya adalah mendapatkan flag dengan cara memalsukan tanda tangan (forge signature) untuk sebuah pesan arbitrer.

Petunjuk utama dari pembuat soal adalah: "Sometime, I've forgot something in somewhere!", yang mengarah pada kesalahan logika saat memvalidasi parameter kurva baru yang kita masukkan.

2. Analisis Kerentanan (Vulnerability Analysis)

Terdapat dua kelemahan fatal yang sengaja ditinggalkan pada source code chall.py:

A. Validasi Faktor Ordo Kurva yang Lemah (any vs all)

Ketika kita memilih menu untuk mengganti parameter kurva, server meminta koefisien $a$ dan $b$, lalu memvalidasi ordo kurva yang baru dengan kode berikut:

factors = factor(n)
B = 2**60
assert any(f[0] > B for f in factors), "OOPS, You've cheated!"


Fungsi any() menyebabkan server hanya mengecek apakah ada setidaknya satu faktor prima yang lebih besar dari $2^{60}$. Jika pembuat soal menggunakan all(), maka semua faktor harus besar (yang mana itu aman). Akibat dari kesalahan ini, kita bebas memasukkan kurva dengan ordo $N = q \cdot S$, di mana $q > 2^{60}$ adalah satu-satunya bilangan prima besar, dan sisa faktornya ($S$) adalah kumpulan bilangan prima yang sangat kecil (smooth).

B. Ruang Kunci Privat Terbatas (Small Key Space)

Kunci privat (priv_key atau $d$) dibuat dengan cara yang sangat tidak aman:

Alphabet = "abcdefghijklmnopqrstuvwxyz"
priv_key =  random.choices(Alphabet, k=21)
priv_key = bytes_to_long(''.join(priv_key).encode())


Kunci privat dipaksa hanya berisi kombinasi 21 karakter alfabet kecil (a-z). Ini berarti panjang maksimal kunci hanyalah 21 byte (kurang dari $2^{168}$ bit). Lebih jauh lagi, karena hanya menggunakan karakter ASCII 0x61 hingga 0x7a, struktur bit-nya sangat tertebak.

3. Skenario Eksploitasi

Untuk mendapatkan flag, kita harus menemukan nilai $d$ (kunci privat). Karena kita bisa menyuntikkan kurva yang ordonya sebagian besar smooth, kita dapat menggunakan Pohlig-Hellman Attack.

Berikut adalah langkah-langkah eksploitasinya:

Langkah 1: Mencari Kurva "Smooth" Sebagian
Saat server memberikan nilai modulo $p$ yang baru, kita melakukan brute-force secara lokal untuk mencari sepasang $a$ dan $b$ sehingga kurva $E(\mathbb{F}_p)$ memiliki ordo $N = q \cdot S$.

$q > 2^{60}$ (agar lolos dari assert server).

$S > 2^{145}$ (agar sisa modulo cukup besar mendekati ukuran kunci privat $2^{168}$).

$S$ harus smooth (faktor prima terbesarnya relatif kecil, misal $< 2^{48}$) agar kalkulasi Discrete Log berjalan cepat.

Langkah 2: Proyeksi Subgrup (Subgroup Confinement)
Setelah mengirim $a$ dan $b$ ke server, server membalas dengan Base point baru $G$ dan Public key $Q = dG$.
Kita kalikan kedua titik tersebut dengan prime besar $q$:

$G' = q \cdot G$

$Q' = q \cdot Q$
Sekarang, $G'$ dan $Q'$ secara murni berada di dalam subgrup berordo $S$.

Langkah 3: Pohlig-Hellman Attack
Karena ordo subgrup $S$ sangat smooth, kita dapat dengan mudah memecahkan Discrete Logarithm Problem (DLP) menggunakan algoritma Pohlig-Hellman di SageMath:


$$d_{S} \equiv \log_{G'} Q' \pmod S$$


Sekarang kita memiliki $d_{S} = d \pmod S$.

Langkah 4: Local Bruteforce
Kita tahu bahwa $d \equiv d_{S} \pmod S$, yang artinya nilai $d$ yang asli adalah $d = k \cdot S + d_{S}$ untuk suatu integer $k$. Karena ukuran $d$ kurang dari $2^{168}$ dan $S > 2^{145}$, nilai $k$ sangatlah kecil (hanya berkisar jutaan kemungkinannya).

Kita buat looping lokal untuk menguji nilai $k$. Untuk setiap kandidat $d$, kita ubah menjadi bytes dan periksa apakah keseluruhannya terdiri dari huruf a sampai z ASCII (rentang 0x61 - 0x7a). Jika ya, kita telah menemukan private key eksaknya!

Langkah 5: Forge Signature
Dengan private key di tangan (contoh: aoyzrsogrhfchngczvpox), kita buat signature palsu $(r, s)$ untuk sembarang pesan (misalnya: give_me_flag) secara lokal, lalu kirimkan ke menu "Get flag" di server untuk mendapatkan flag.

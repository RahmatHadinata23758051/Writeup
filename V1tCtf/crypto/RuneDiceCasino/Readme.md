CTF Writeup: Rune Dice Casino

Kategori: Cryptography

Difficulty: Hard / Insane

Topik Utama: LLL (Lattice), CVP, Length Extension Attack, LFSR, Truncated LCG, Bivariate Coppersmith, MT19937 PRNG Forgery.

Ringkasan Tantangan

Rune Dice Casino adalah tantangan kriptografi bertingkat (gauntlet). Untuk mendapatkan flag, kita tidak hanya memecahkan satu jenis enkripsi, melainkan enam lapis gerbang keamanan (gates) yang diurutkan secara sekuensial. Kegagalan di satu titik berarti server akan memutus koneksi.

Tujuan akhirnya adalah memalsukan putaran dadu (Mersenne Twister) untuk memenangkan Jackpot. Namun, untuk memalsukannya, kita butuh nilai charm (seed utama) yang dikunci dengan polinomial derajat dua. Dan untuk mencapai tahap itu, kita harus menembus Vault, Cashier, LFSR, dan LCG gates.

Berikut adalah walkthrough lengkap beserta teori dan jalan buntu yang dihadapi selama penyelesaian.Gate 1: The Vault Gate (Lattice / CVP)

Teori & Perhitungan Matematis

Server membuat sebuah matriks $M$ berukuran $6 \times 18$ dan sebuah vektor rahasia $s$ berisi 18 elemen (berukuran 64-bit). Kita diberikan matriks $M$ dan hasil kali $t = M \cdot s \pmod N$. Kita harus mencari $s$.

Ini adalah variasi dari Learning With Errors (LWE) atau masalah Knapsack, namun tanpa noise. Karena ini adalah sistem persamaan linear modular dengan target vektor yang diketahui, kita dapat mereduksinya menjadi Closest Vector Problem (CVP) dan menyelesaikannya dengan Kannan's Embedding Technique melalui algoritma LLL.

Kita membentuk matriks basis Lattice $B$ berukuran $(18+6+1) \times (18+6+1)$:

$$B = \begin{pmatrix}
I_{18} & M \cdot K \\
0 & N \cdot I_6 \cdot K \\
0 & -t \cdot K
\end{pmatrix}$$

Di mana $K$ adalah bobot (weight) yang sangat besar (misal $2^{128}$) untuk memaksa LLL memprioritaskan persamaan agar sama dengan nol.

Eksekusi

Dengan memasukkan matriks ini ke SageMath dan memanggil .LLL(), vektor terpendek yang dihasilkan akan mengandung elemen rahasia $s$ di 18 kolom pertamanya (dengan tanda positif atau negatif tergantung pada pengali baris terakhir). Gate 1 berhasil dilewati.Gate 2: Cashier Gate (Length Extension Attack)

Teori & Perhitungan Matematis

Kita diberikan sebuah message (name=guest&table=rune-dice&admin=false) dan sebuah MAC berbasis SHA-256: MAC = SHA256(SECRET + msg). Panjang SECRET diketahui (16 byte). Kita harus membuat pesan baru yang mengandung &admin=true dan membuat MAC yang valid untuk pesan tersebut, tanpa mengetahui rahasianya.

Ini adalah kerentanan klasik fungsi hash keluarga Merkle-Damgård (termasuk SHA-256). Karena state internal SHA-256 hanya bergantung pada blok sebelumnya, kita bisa mengambil nilai MAC asli, memecahnya menjadi 8 register (A hingga H), dan melanjutkannya untuk menghitung blok append buatan kita.

Jalan Buntu 1: C-Macro Cthulhu

Awalnya, kita menggunakan modul Python standar untuk serangan ini, yaitu hashpumpy. Namun, saat dijalankan di dalam environment SageMath dengan Python 3.12, kita dihantam error:
SystemError: PY_SSIZE_T_CLEAN macro must be defined for '#' formats

Analisis: Ini adalah bug kompatibilitas di mana source code hashpumpy (yang ditulis dalam C) belum diperbarui untuk aturan API Python 3.10+.
Solusi: Membuang hashpumpy dan menulis ulang fungsi SHA-256 internal state override murni menggunakan Python (_sha256_process).

Jalan Buntu 2: The SageMath Preparser Trap

Setelah menulis algoritma SHA-256 dengan Python murni, skrip memakan seluruh memori (RAM) dan crash dengan pesan:
OverflowError: exponent must be at most 9223372036854775807

Analisis: Di dalam Python murni, ^ adalah operator Bitwise XOR. Namun, kita menjalankan skrip dengan sage solve.sage. Preparser bawaan SageMath menerjemahkan ^ sebagai Eksponen (Perpangkatan). SHA-256 sangat bergantung pada operasi XOR. Alih-alih melakukan XOR, skrip mencoba memangkatkan angka 32-bit dengan angka 32-bit lainnya, menghasilkan angka raksasa yang membuat memori overflow.
Solusi: Mengganti semua operator ^ menjadi ^^ (operator XOR khusus di SageMath) di seluruh fungsi kriptografi manual kita. Gate 2 akhirnya tertembus!

Gate 3: Wheel of Linear Fate (LFSR)

Teori & Perhitungan Matematis

Kita berhadapan dengan Linear Feedback Shift Register (LFSR) derajat 96. Kita diberikan urutan 208 bit observasi dan harus menebak 128 bit berikutnya.

LFSR sangat lemah terhadap aljabar linear. Setiap bit observasi ke-$n$ dapat ditulis sebagai kombinasi linear dari 96 bit sebelumnya di atas Galois Field 2 ($GF(2)$):


$$s_{n+96} = c_0 s_n + c_1 s_{n+1} + \dots + c_{95} s_{n+95} \pmod 2$$

Eksekusi

Kita menyusun 208 bit observasi tersebut menjadi matriks berukuran $112 \times 96$ dan vektor hasil $112 \times 1$. Dengan memanggil M.solve_right(v) di lingkungan $GF(2)$ SageMath, kita langsung mendapatkan array taps ($c_0 \dots c_{95}$). Menebak 128 bit selanjutnya tinggal mengalikan state terakhir dengan taps tersebut. Gate 3 lolos dengan sangat mulus.

Gate 4: LCG Slots (Truncated LCG)

Teori & Perhitungan Matematis

Kita dihadapkan pada generator pseudo-random Linear Congruential Generator (LCG): $X_{n+1} = (a \cdot X_n + c) \pmod M$.
Nilai $a, c,$ dan $M = 2^{64}$ diketahui. Tantangannya: kita hanya diberikan 22 bit paling atas (Most Significant Bits) dari 8 status berurutan (bocoran). Kita harus menebak 8 status berikutnya.

Setiap status aktual $X_i$ dapat direpresentasikan sebagai $X_i = leak_i \cdot 2^{42} + k_i$, di mana $k_i$ adalah 42 bit yang hilang.
Dengan substitusi persamaan LCG, masalah ini kembali bisa direduksi menjadi sistem persamaan LLL (Lattice).

 Jalan Buntu 3: Off-By-One (Blind Send)

Skrip berhasil menghitung status seed awal, namun saat jawaban dikirim, server langsung memutus koneksi secara sepihak (EOFError). Tidak ada pesan error, hanya koneksi yang mati.

Analisis: Prediksi LCG kita ditolak (server mencetak "The slot machine locks" lalu memutus koneksi). Setelah menelusuri algoritma iterasi kita, ternyata kita memutar perulangan LCG sebanyak $n$ kali (8 kali) dari state 0. Hal ini menyebabkan status tergeser sebanyak satu indeks (Off-By-One Error). Tebakan pertama kita yang seharusnya untuk iterasi ke-9, malah berisi iterasi ke-10.
Solusi: Mengurangi loop skip awal menjadi n - 1. LLL mengembalikan status ke-1, digulirkan 7 kali, dan tebakan dimulai pas di status ke-9. Gate 4 jebol!

Gate 5: Booth (Bivariate Coppersmith)

Teori & Perhitungan Matematis

Inilah kunci utama tantangan. Sebuah charm 32-byte dibagi menjadi dua: $m_1$ dan $m_0$. Kita diberikan persamaan kuadratik dalam modulus $N$ (RSA-like modulus, 1036 bit):


$$a m_1^2 + b m_0^2 + c m_1 m_0 + d m_1 + e m_0 + f \equiv 0 \pmod N$$

Ini adalah masalah mencari akar kecil dari polinomial dua variabel (Bivariate Coppersmith). Karena $m_1, m_0 < 2^{128}$ (cukup kecil dibanding $N \approx 2^{1036}$), kita bisa menggunakan LLL.

Kalikan persamaan dengan invers $a$ agar monik: $P(x,y) \equiv 0 \pmod N$.

Susun matriks shift polinomial menggunakan monom $(1, x, y, y^2, xy, \dots, x^2y)$.

Terapkan LLL. Baris matriks yang direduksi akan menghasilkan persamaan polinomial ekuivalen atas integer $\mathbb{Z}$ (bukan modulus $N$).

Ekstraksi dua persamaan baru, lalu hitung Resultant terhadap $y$ untuk mengeliminasi variabel $y$.

Cari akar $x$ (yaitu $m_1$), substitusi balik untuk mendapat $y$ (yaitu $m_0$).

Jalan Buntu 4: Type Mismatch

Skrip crash saat menyusun matriks: AttributeError: 'int' object has no attribute 'monomial_coefficient'.
Analisis: SageMath sangat ketat soal tipe data. Array polinomial kita diawali dengan nilai modulus N. N bertipe Integer, bukan PolynomialRing, sehingga tidak memiliki fungsi .monomial_coefficient().
Solusi: Melakukan explicit casting dengan mengubah definisi awal menjadi PR(N) dan mendefinisikan konstanta 1 sebagai PR(1). Proses pencarian polinomial memakan waktu $\pm 15$ detik dan charm berhasil diekstrak!

Gate 6: The Jackpot (MT19937 PRNG Forgery)

Teori & Perhitungan Matematis

Dengan charm di tangan, kita mengetahui seed milik bandar (house). Untuk menang Jackpot, tebakan dadu kita + dadu bandar + penambah jalur harus sama dengan 5 selama 120 putaran tanpa putus (streak).

Kita harus mengirim blok memori (cartridge) berukuran 624 integer (state penuh dari PRNG Mersenne Twister MT19937) milik Python.
Jika kita ingin PRNG mengeluarkan angka tertentu (misal $T$), kita harus melakukan fungsi untemper. Tempering di MT19937 adalah operasi pergeseran bit (XOR dan Shift). Kita bisa menulis fungsi kebalikannya (inverse) untuk menyuntikkan nilai $T$ ke dalam memori $state$.

Jalan Buntu 5: "The Twist Trap" (Score = 317)

Kita membuat 120 tebakan jitu, menaruhnya di array cartridge dari index 0 sampai 119. Saat dikirim, kita hanya mendapat skor 317 (skor kalah / acak). Mengapa?

Typo Untemper: Inverse operasi bit-shift ke kanan milik kita salah. Seharusnya inversi dari 22 bit adalah digeser dua kali (11 dan 22), tapi kita menulisnya 11 dan 11.

The Twist Trap (Jebakan Batman): Server memuat cartridge kita dan menetapkan index baca di 624. Aturan MT19937 menyatakan: Jika index >= 624, panggil fungsi twist() untuk mengacak ulang seluruh isi array! Karena tebakan kita ada di index 0-119, tebakan kita hancur lebur diacak oleh matriks Mersenne Twister sebelum dadu pertama dikocok.

Solusi Jenius (The Twist Bypass)

Fungsi twist() milik MT19937 beroperasi dengan rumus inti:


$$State[i] = State[i+397] \oplus F(State[i], State[i+1])$$


Jika $State[0]$ sampai $State[396]$ bernilai 0, maka $F(0,0)$ adalah 0.
Ini berarti $State[i]$ yang baru, sama persis dengan $State[i+397]$ yang lama!

Kita tidak menaruh tebakan (payload) kita di index 0. Kita menyuntikkan payload kita mulai di index 397.
Ketika server memanggil twist(), aljabar matriks PRNG dengan patuh menyalin payload murni kita dari index 397 dan meletakkannya dengan manis di index 0!

Penyelesaian Akhir

Dengan membenarkan fungsi untemper dan menerapkan trik Twist Bypass, cartridge dimuat, 120 putaran menghasilkan output mutlak angka 5, dan skor memuncak di angka 630 (Melampaui target Jackpot 600).

SCORE = 630
FLAG = V1T{rune_dice_coppersmith_bkz}


Game Over. The Casino is ours.

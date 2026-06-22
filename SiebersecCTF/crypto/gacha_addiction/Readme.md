Writeup: gacha_addiction (Crypto Challenge - SiebersecCTF)

Tantangan kriptografi gacha_addiction menguji pemahaman kita mengenai sifat dasar struktur matematika RSA, khususnya sifat multiplicative homomorphic yang membuka celah terhadap serangan RSA Chosen-Message Attack (RSA Blinding).

1. Analisis Kode Sumber (Source Code Analysis)

Dari file chall.py yang diberikan, berikut adalah poin-point arsitektur penting dari sistem oracle tersebut:

Variabel Awal:

Jumlah pull awal kita: pulls = 50.

Pity gacha kita dimulai dari: pull_count = 0.

Pesan kupon target yang ingin kita tandatangani: coupon = b'Winning5050sFORFREE'.

Kunci RSA & Flag:

Menggenerasikan dua buah bilangan prima acak 1024-bit ($p$ dan $q$) untuk membuat modulus $n = p \cdot q$.

Eksponen enkripsi publik standar $e = 65537$.

Eksponen dekripsi privat $d$ dihitung dengan $d \equiv e^{-1} \pmod{\phi(n)}$.

Flag dienkripsi menggunakan skema enkripsi buku teks (textbook RSA):


$$ciphertext \equiv flag^e \pmod n$$

Batasan Oracle:

Opsi 1 (Tanda Tangan): Kita dapat meminta oracle untuk menandatangani pesan apa pun ($M$) menjadi $S \equiv M^d \pmod n$. Namun, oracle melarang kita menandatangani pesan kupon secara langsung:

if user_message == message or user_message < 0 or user_message >= n or user_message == ciphertext:
    print('we cannot sign this message >:(')


Opsi 2 (Redeem Kupon): Jika kita dapat menyerahkan nilai tanda tangan $S$ sedemikian rupa sehingga $S^e \equiv message \pmod n$, kita akan mendapatkan tambahan $50$ pulls sehingga total pulls menjadi $100$.

Opsi 3 (Gacha / Pull): Setiap kali melakukan pull, total pulls berkurang 1 dan counter pity bertambah 1. Apabila kita berhasil menyentuh angka pity tepat 90, oracle akan membocorkan salah satu faktor prima asli pembangun modulus, yaitu nilai $p$:

elif pull_count == 90:
    print('hard pity reached! here is your p!')
    print(f'{p = }')


2. Kerentanan Kritis: Multiplicative Homomorphic RSA

Karena biner menggunakan RSA tanpa skema padding aman seperti OAEP atau PSS (textbook RSA), skema ini memiliki sifat homomorfik perkalian:


$$(M_1 \cdot M_2)^d \equiv M_1^d \cdot M_2^d \pmod n$$

Dengan sifat ini, kita dapat melakukan teknik penyamaran pesan (RSA Blinding):

Kita tentukan sebuah nilai faktor pengacak (blinding factor), misalnya $X = 2$.

Hitung pesan yang disamarkan ($M'$):


$$M' \equiv M \cdot X^e \pmod n$$

Karena nilai $M'$ jelas berbeda dengan $M$ asli (kupon), oracle pada Opsi 1 dengan senang hati akan menandatanganinya dan mengembalikan nilai $S'$:


$$S' \equiv (M')^d \equiv (M \cdot X^e)^d \equiv M^d \cdot X^{e \cdot d} \equiv M^d \cdot X \pmod n$$

Untuk mendapatkan tanda tangan asli ($S$) dari kupon, kita tinggal membagi (mengalikan dengan invers modular) nilai $S'$ dengan faktor pengacak kita ($X$):


$$S \equiv S' \cdot X^{-1} \pmod n$$

3. Alur Rencana Eksploitasi

Hubungkan ke server remote untuk mengambil nilai kunci publik $n$, $e$, dan $ciphertext$.

Konversi kupon b'Winning5050sFORFREE' menjadi representasi integer ($M$).

Lakukan proses Blinding dengan $X = 2$ untuk mendapatkan $M'$.

Kirim $M'$ ke menu penandatanganan (Opsi 1) untuk mendapatkan $S'$.

Hitung invers modular $2^{-1} \pmod n$ dan kalikan dengan $S'$ untuk mendapatkan tanda tangan kupon $S$.

Kirim $S$ ke menu redeem kupon (Opsi 2) untuk mengklaim tambahan $50$ pulls.

Lakukan gacha (Opsi 3) sebanyak 91 kali (90 kali untuk menaikkan pity ke 90, dan 1 kali lagi untuk memicu keluarnya informasi prima $p$).

Setelah prima $p$ didapatkan, cari faktor kedua: $q = n / p$.

Hitung nilai Euler totient: $\phi(n) = (p-1)(q-1)$.

Cari eksponen privat: $d \equiv e^{-1} \pmod{\phi(n)}$.

Dekripsi ciphertext untuk mendapatkan flag: $flag \equiv ciphertext^d \pmod n$.

4. Skrip Solusi (solve.py)

Berikut adalah kode otomatisasi penyelesaian tantangan menggunakan Python pwntools dan pustaka kriptografi pycryptodome:

from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

# 1. Inisialisasi Koneksi ke Server Target
p = remote('chal.sieberr.live', 20000)

# Parsing Nilai n, e, dan Ciphertext dari Banner Utama
p.recvuntil(b'n = ')
n = int(p.recvline().strip())
p.recvuntil(b'e = ')
e = int(p.recvline().strip())
p.recvuntil(b'ciphertext = ')
ciphertext = int(p.recvline().strip())

log.info(f"Modulus N: {str(n)[:20]}...")
log.info(f"Ciphertext: {str(ciphertext)[:20]}...")

# Nilai kupon yang harus ditandatangani
coupon = b'Winning5050sFORFREE'
M = bytes_to_long(coupon)

# 2. RSA Blinding (Menyamarkan Pesan Kupon)
X = 2
M_prime = (M * pow(X, e, n)) % n

# Meminta tanda tangan pesan samaran (Opsi 1)
p.sendlineafter(b'What will your choice be(1/2/3/4): ', b'1')
p.sendlineafter(b'Please input the message to sign: ', str(M_prime).encode())
p.recvuntil(b'your signed message is: ')
S_prime = int(p.recvline().strip())

# Proses Unblinding (Mendapatkan Tanda Tangan Kupon Asli)
X_inv = pow(X, -1, n)
S = (S_prime * X_inv) % n

# 3. Menebus Tanda Tangan Kupon Asli (Opsi 2)
p.sendlineafter(b'What will your choice be(1/2/3/4): ', b'2')
p.sendlineafter(b'please input your signed message: ', str(S).encode())
log.success("Kupon berhasil diklaim! Sisa pull bertambah menjadi 100.")

# 4. Melakukan Gacha sebanyak 91 kali untuk memicu Hard Pity
log.info("Memulai proses gacha massal sebanyak 91 kali...")
for i in range(91):
    p.sendlineafter(b'What will your choice be(1/2/3/4): ', b'3')

# Parsing nilai prima p asli
p.recvuntil(b'p = ')
p_factor = int(p.recvline().strip())
log.success(f"Hard Pity tercapai! Prima P didapatkan: {str(p_factor)[:20]}...")

# 5. Rekonstruksi Kunci & Dekripsi Flag
q_factor = n // p_factor
phi = (p_factor - 1) * (q_factor - 1)
d = pow(e, -1, phi)

# Dekripsi data flag
flag_long = pow(ciphertext, d, n)
flag = long_to_bytes(flag_long)

log.success(f"Flag Ditemukan: {flag.decode()}")
p.close()


5. Kesimpulan

Tantangan gacha_addiction membuktikan bahwa implementasi skema tanda tangan digital menggunakan arsitektur textbook RSA (tanpa padding acak seperti PSS) sangat rentan terhadap manipulasi nilai eksponensial modular. Penggunaan skema padding standar industri sangat diwajibkan untuk mengamankan proses validasi pesan sensitif.

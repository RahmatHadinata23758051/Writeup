Writeup CTF: Quantum Echo (Cryptography)

Nama Tantangan: Quantum Echo

Kategori: Cryptography

Poin: 100

Flag: TBCTF{C0mm0n_Pr1m3s_Ar3_D34dly}

1. Analisis Deskripsi & Berkas

Diberikan deskripsi tantangan sebagai berikut:

"The Quantum Echo Research Facility thought their secrets were bulletproof — locked away behind the impenetrable walls of asymmetric cryptography. But somewhere in their rush to deploy, something went terribly wrong. Two keys. One message. Can you hear the echo?"

Kita juga diberikan tiga buah berkas:

ciphertext.txt (berisi pesan terenkripsi dalam bentuk integer besar)

public1.pem (Kunci publik RSA pertama)

public2.pem (Kunci publik RSA kedua)

2. Analisis Kerentanan (Vulnerability Analysis)

Dalam kriptografi RSA, kunci publik terdiri dari pasangan $(N, e)$, di mana $N$ adalah modulus hasil perkalian dua bilangan prima besar $p$ dan $q$ ($N = p \times q$), sedangkan $e$ adalah eksponen enkripsi.

Ketika ada dua kunci publik berbeda yang dibuat secara ceroboh (misalnya menggunakan generator bilangan acak yang buruk), ada kemungkinan kedua kunci tersebut berbagi salah satu bilangan prima yang sama ($p$).

Jika:


$$N_1 = p \times q_1$$

$$N_2 = p \times q_2$$

Maka kita bisa mencari faktor prima bersama tersebut dengan sangat cepat menggunakan algoritma Greatest Common Divisor (GCD) tanpa perlu melakukan faktorisasi paksa (brute-force):


$$p = \gcd(N_1, N_2)$$

Setelah nilai $p$ ditemukan, kita bisa mencari $q_1$ atau $q_2$:


$$q_1 = \frac{N_1}{p}$$

Dengan mengetahui nilai $p$ dan $q_1$, kita dapat menghitung nilai Totient Euler $\phi(N_1)$ dan kunci privat dekripsi $d_1$:


$$\phi(N_1) = (p - 1)(q_1 - 1)$$

$$d_1 \equiv e_1^{-1} \pmod{\phi(N_1)}$$

Terakhir, kita dekripsi ciphertext $c$ untuk mendapatkan kembali pesan asli $m$:


$$m \equiv c^{d_1} \pmod{N_1}$$

3. Langkah Penyelesaian (Exploitation)

Berikut adalah script otomatis menggunakan Python dan pustaka pycryptodome untuk mengekstrak kunci, mencari GCD, melakukan dekripsi, dan menerjemahkan hasilnya menjadi teks biasa (flag):

from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes
import math

# 1. Load berkas public key dan ciphertext
with open("public1.pem", "r") as f:
    key1 = RSA.import_key(f.read())

with open("public2.pem", "r") as f:
    key2 = RSA.import_key(f.read())

with open("ciphertext.txt", "r") as f:
    c = int(f.read().strip().replace('%', ''))

n1, e1 = key1.n, key1.e
n2, e2 = key2.n, key2.e

print(f"[*] N1: {n1}\n")
print(f"[*] N2: {n2}\n")

# 2. Hitung GCD dari kedua modulus
p = math.gcd(n1, n2)

if p > 1 and p != n1:
    print(f"[+] Ditemukan faktor prima bersama (p): {p}\n")
    
    # Hitung q untuk modulus pertama
    q1 = n1 // p
    
    # Hitung phi dan private exponent (d)
    phi1 = (p - 1) * (q1 - 1)
    d1 = pow(e1, -1, phi1)
    
    # Dekripsi ciphertext
    m = pow(c, d1, n1)
    
    # Konversi integer ke byte (string)
    flag = long_to_bytes(m)
    print(f"[🎉] FLAG: {flag.decode(errors='ignore')}")
else:
    print("[-] Kedua modulus tidak berbagi faktor prima.")


4. Kesimpulan

Tantangan ini berhasil diselesaikan dengan memanfaatkan kelemahan pembuatan kunci RSA yang menghasilkan bilangan prima yang sama (Shared/Common Prime). Dengan menggunakan operasi matematika dasar GCD yang sangat cepat, kita dapat memfaktorkan modulus besar $N$ dalam hitungan milidetik dan memulihkan kunci privat untuk mendapatkan flag:

Flag: TBCTF{C0mm0n_Pr1m3s_Ar3_D34dly}

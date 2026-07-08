CTF Writeup: Whispering (LyknCTF 2026)

Kategori: Cryptography

Tingkat Kesulitan: Medium

Flag: LYKNCTF{c85ccad898a34224aa92a2f1ae9ecae5}

Deskripsi Tantangan

Tantangan ini mengimplementasikan sistem kriptografi berbasis kisi (lattice-based) mirip NTRU pada cincin polinomial:

$$\mathbb{Z}_q[x]/(x^N - 1)$$

Dengan parameter:

$N = 127$

$q = 2048$

$p = 3$

$q' = 2053$

Flag enkripsi menggunakan AES-CBC, di mana kunci enkripsinya diturunkan melalui HKDF menggunakan sebuah algebraic signature ($V$) yang dihitung dari kunci privat $f$ dan $g$:

$$V = \sum (f \cdot g) \pmod{q'}$$

Meskipun $f$ dan $g$ dirahasiakan, kita diberikan beberapa informasi tambahan (leakage) melalui endpoint /side_channel.json berupa:

Jumlah koefisien berindeks genap (even) dan ganjil (odd) dari $f$ dan $g$ dalam modulo $127$.

Analisis Celah Keamanan (The Vulnerability)

Kerentanan fatal dari skema ini terletak pada bagaimana algebraic signature ($V$) didefinisikan dan dihitung.

1. Homomorfisma Penjumlahan Polinomial

Diberikan dua buah polinomial $f(x)$ dan $g(x)$, perkalian konvolusi mereka adalah $h(x) = f(x) \cdot g(x)$. Ada identitas aljabar mendasar yang menyatakan bahwa jumlah dari seluruh koefisien polinomial hasil perkalian selalu sama dengan hasil kali dari jumlah koefisien masing-masing polinomial komponennya.

Secara matematis:

$$\sum (f \cdot g) = \left(\sum f\right) \times \left(\sum g\right)$$

Sehingga nilai signature $V$ dapat disederhanakan menjadi:

$$V \equiv \left(\sum f\right) \times \left(\sum g\right) \pmod{q'}$$

Dengan demikian, kita tidak perlu memecahkan masalah kisi NTRU atau mencari polinomial $f$ dan $g$ secara penuh. Kita hanya perlu mengetahui nilai skalar dari total penjumlahan koefisien $\sum f$ dan $\sum g$.

2. Rekonstruksi Nilai Sum Melalui Center Lift

Dari bocoran side-channel, kita diberikan:

$f_{\text{even}} \pmod{127}$ dan $f_{\text{odd}} \pmod{127}$

$g_{\text{even}} \pmod{127}$ dan $g_{\text{odd}} \pmod{127}$

Koefisien dari $f$ dan $g$ dibatasi pada nilai ternari $\{-1, 0, 1\}$. Karena derajat polinomial adalah $N = 127$, jumlah koefisien pada posisi genap maksimal adalah $64$, dan ganjil maksimal adalah $63$.

Karena nilai jangkauan penjumlahan asli dari komponen ganjil maupun genap berada dalam rentang $[-64, 64]$—yang mana rentang ini berada di dalam batas setengah dari modulus bocoran ($127$)—kita dapat menerapkan teknik Center Lift untuk memulihkan nilai asli sebelum operasi modulo dilakukan:

$$\text{CenterLift}(x, m) = 
\begin{cases} 
x - m & \text{jika } x > \frac{m}{2} \\
x & \text{lainnya}
\end{cases}$$

Setelah mendapatkan nilai asli dari masing-masing komponen, kita tinggal menjumlahkannya untuk mendapatkan total penjumlahan koefisien:

$$\sum f = \text{CenterLift}(f_{\text{even}}, 127) + \text{CenterLift}(f_{\text{odd}}, 127)$$

$$\sum g = \text{CenterLift}(g_{\text{even}}, 127) + \text{CenterLift}(g_{\text{odd}}, 127)$$

3. Menghitung Kunci Dekripsi

Setelah mendapatkan $\sum f$ dan $\sum g$, kita hitung nilai signature $V$:

$$V = \left(\sum f \times \sum g\right) \pmod{2053}$$

Nilai $V$ ini kemudian langsung dimasukkan ke dalam fungsi KDF (HKDF-SHA256) untuk merekonstruksi kunci AES-CBC dan mendekripsi bendera (flag).

Skrip Eksploitasi (Python)

Skrip berikut melakukan pengambilan data dari server tantangan, memulihkan nilai $V$ menggunakan celah matematika di atas, merekonstruksi kunci AES, dan mendekripsi cipher flag secara instan.

import requests
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import unpad

# URL Server Instance (Sesuaikan dengan instance aktif Anda)
BASE_URL = "[http://257b4d35-2463-4079-b6a7-3b941a58e977.51.79.140.18.nip.io:8080](http://257b4d35-2463-4079-b6a7-3b941a58e977.51.79.140.18.nip.io:8080)"

print("[*] Mengambil data publik dan side-channel...")
public_data = requests.get(f"{BASE_URL}/public.json").json()
side_channel = requests.get(f"{BASE_URL}/side_channel.json").json()

# Ekstrak Parameter
N = public_data["parameters"]["N"]
q = public_data["parameters"]["q"]
q_prime = public_data["parameters"]["q_prime"]

enc_flag = public_data["encrypted_flag"]
ciphertext = bytes.fromhex(enc_flag["ciphertext"])
iv = bytes.fromhex(enc_flag["iv"])
salt = enc_flag["salt"]

# Ekstrak Bocoran Side-Channel
constraints = side_channel["constraints"]
f_even_mod = constraints["f_even_sum_mod_127"]
f_odd_mod = constraints["f_odd_sum_mod_127"]
g_even_mod = constraints["g_even_sum_mod_127"]
g_odd_mod = constraints["g_odd_sum_mod_127"]

def center_lift(val, mod=127):
    """Memetakan kembali nilai modulo ke rentang asli [-63, 64]"""
    return val - mod if val > mod // 2 else val

# 1. Melakukan pemulihan nilai penjumlahan koefisien asli
f_even = center_lift(f_even_mod)
f_odd = center_lift(f_odd_mod)
g_even = center_lift(g_even_mod)
g_odd = center_lift(g_odd_mod)

sum_f = f_even + f_odd
sum_g = g_even + g_odd

# 2. Menghitung V (Algebraic Signature) langsung tanpa memecahkan NTRU
V = (sum_f * sum_g) % q_prime
print(f"[+] Nilai V (Algebraic Signature) berhasil dipulihkan: {V}")

# 3. Merekonstruksi Master Key menggunakan HKDF
ikm = (
    V.to_bytes(4, "big")
    + N.to_bytes(2, "big")
    + q.to_bytes(2, "big")
    + salt.encode("utf-8")
)

key = HKDF(
    master=ikm,
    key_len=32,
    salt=str(N).encode("utf-8"),
    hashmod=SHA256,
)

# 4. Mendekripsi Flag menggunakan AES-CBC
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(ciphertext)

try:
    flag = unpad(decrypted, AES.block_size).decode()
    print(f"\n[+] FLAG DITEMUKAN: {flag}")
except Exception as e:
    print(f"[-] Gagal melakukan dekripsi (kemungkinan kalkulasi key salah): {e}")

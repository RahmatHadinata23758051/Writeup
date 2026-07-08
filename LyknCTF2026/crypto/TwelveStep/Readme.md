CTF Writeup: Twelve Steps (LyknCTF 2026)

Kategori: Cryptography

Tingkat Kesulitan: Easy - Medium

Flag: LYKNCTF{a8fda63902674a679e0d7d4fd088aab1}

Deskripsi Tantangan

Tantangan ini meminta kita menebak nilai berikutnya ($out[12]$) dari sebuah generator angka acak semu yang menggunakan algoritma Linear Congruential Generator (LCG).

Rumus dasar LCG adalah:


$$s_{n+1} = (a \cdot s_n + c) \pmod m$$

Di mana parameter multiplier ($a$), increment ($c$), modulus ($m$), dan seed ($s_0$) dirahasiakan. Kita diberikan $12$ output berurutan ($s_0$ hingga $s_{11}$) dan harus memprediksi $s_{12}$ untuk mendapatkan flag.

Analisis Matematika (Memecahkan LCG)

Meskipun $a$, $c$, dan $m$ dirahasiakan, kita dapat merekonstruksinya secara matematis jika memiliki minimal $6$ buah output berurutan.

1. Menentukan Modulus ($m$)

Kita definisikan selisih antar state yang berurutan sebagai:


$$d_n = s_{n+1} - s_n$$

Berdasarkan rumus LCG:


$$s_{n+2} \equiv a \cdot s_{n+1} + c \pmod m$$

$$s_{n+1} \equiv a \cdot s_n + c \pmod m$$

Jika kita kurangkan kedua persamaan di atas, konstanta $c$ akan saling menghilangkan:


$$s_{n+2} - s_{n+1} \equiv a(s_{n+1} - s_n) \pmod m$$

$$d_{n+1} \equiv a \cdot d_n \pmod m$$

Dari relasi ini, kita dapat menyusun determinan dari matriks transisi untuk mengeliminasi nilai $a$:


$$d_{n+2} \equiv a \cdot d_{n+1} \pmod m$$

$$d_{n+1} \equiv a \cdot d_n \pmod m$$

Kalikan silang kedua kongruensi:


$$d_{n+2} \cdot d_n \equiv a \cdot d_{n+1} \cdot d_n \equiv d_{n+1}^2 \pmod m$$

$$d_{n+2} \cdot d_n - d_{n+1}^2 \equiv 0 \pmod m$$

Artinya, untuk setiap indeks $n$, nilai $t_n = d_{n+2} \cdot d_n - d_{n+1}^2$ merupakan kelipatan dari modulus $m$. Kita dapat mencari $m$ dengan menghitung Greatest Common Divisor (GCD) dari beberapa nilai $t_n$:


$$m = \gcd(t_0, t_1, t_2, \dots)$$

2. Menentukan Multiplier ($a$)

Setelah mendapatkan modulus $m$, kita dapat mencari pengali $a$ melalui hubungan:


$$d_{n+1} \equiv a \cdot d_n \pmod m$$

Secara teoretis, jika $\gcd(d_n, m) = 1$, kita bisa langsung menggunakan modular inverse:


$$a \equiv d_{n+1} \cdot d_n^{-1} \pmod m$$

Namun, jika $\gcd(d_n, m) > 1$, modular inverse biasa tidak akan ada (menyebabkan error). Kita harus menyelesaikan persamaan linear kongruensi $ax \equiv b \pmod m$ dengan mereduksi seluruh komponen persamaan menggunakan nilai $\gcd$ tersebut:


$$g = \gcd(d_n, m)$$

$$a' \cdot d_n' \equiv d_{n+1}' \pmod{m'}$$


Di mana $d_n' = d_n / g$, $d_{n+1}' = d_{n+1} / g$, dan $m' = m / g$. Sekarang $\gcd(d_n', m') = 1$ terjamin, sehingga kita bisa mencari modular inverse untuk mendapatkan solusi umum dari $a$.

3. Menentukan Increment ($c$)

Setelah mendapatkan $a$ dan $m$, konstanta $c$ dapat dengan mudah dicari dari persamaan awal:


$$c \equiv s_{1} - a \cdot s_0 \pmod m$$

Setelah ketiga parameter ditemukan, kita bisa memprediksi nilai ke-13 ($s_{12}$):


$$s_{12} = (a \cdot s_{11} + c) \pmod m$$

Skrip Eksploitasi (Python)

Berikut adalah skrip Python menggunakan pustaka pwntools yang secara otomatis terhubung ke server, mengambil $12$ output, memecahkan parameter LCG secara tangguh (robust terhadap ketiadaan modular inverse biasa), menghitung prediksi, mengirimkannya, dan mencetak flag.

from pwn import *
from math import gcd
from functools import reduce

# Konfigurasi target
HOST = '51.79.140.18'
PORT = 15937

def solve_linear_congruence(a, b, m):
    """Menyelesaikan persamaan ax ≡ b (mod m) bahkan jika gcd(a, m) > 1"""
    g = gcd(a, m)
    if b % g != 0:
        return None  # Tidak ada solusi yang valid
    
    # Reduksi persamaan menggunakan GCD
    a_prime = a // g
    b_prime = b // g
    m_prime = m // g
    
    # Sekarang gcd(a_prime, m_prime) pasti 1, aman menggunakan pow()
    try:
        x = (b_prime * pow(a_prime, -1, m_prime)) % m_prime
        return x
    except ValueError:
        return None

def crack_lcg(states):
    # 1. Menghitung Modulus (m)
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zero_mods = [d2 * d0 - d1**2 for d0, d1, d2 in zip(diffs, diffs[1:], diffs[2:])]
    m = abs(reduce(gcd, zero_mods))
    
    # 2. Menghitung Multiplier (a)
    a = None
    for i in range(len(diffs) - 1):
        sol = solve_linear_congruence(diffs[i], diffs[i+1], m)
        if sol is not None:
            a = sol
            # Validasi apakah 'a' ini konsisten pada relasi berikutnya
            if (diffs[i+1] - a * diffs[i]) % m == 0:
                break
                
    if a is None:
        raise Exception("Gagal mencari nilai 'a' yang valid.")

    # 3. Menghitung Increment (c)
    c = (states[1] - states[0] * a) % m
    
    return a, c, m

# Inisiasi koneksi interaktif
r = remote(HOST, PORT)

# Lewati banner pengantar sampai bagian output dimulai
r.recvuntil(b"Here are 12 consecutive outputs:\n")

# Parsing 12 baris output angka dari server
outputs = []
for i in range(12):
    line = r.recvline().decode().strip()
    val = int(line.split('=')[1].strip())
    outputs.append(val)

print(f"[+] Output yang diterima: {outputs}")

# Memecahkan LCG
print("[*] Melakukan kalkulasi parameter LCG (a, c, m)...")
try:
    a, c, m = crack_lcg(outputs)
    print(f"[+] LCG Terpecahkan!")
    print(f"  a = {a}")
    print(f"  c = {c}")
    print(f"  m = {m}")

    # Menghitung prediksi out[12]
    next_val = (a * outputs[-1] + c) % m
    print(f"[+] Prediksi out[12]: {next_val}")

    # Mengirimkan jawaban sebelum timeout
    r.recvuntil(b"out[12] = ")
    r.sendline(str(next_val).encode())

    # Membaca flag dari respon server
    print("[*] Mengambil flag dari server...")
    print(r.recvall().decode())

except Exception as e:
    print(f"[-] Terjadi kesalahan: {e}")
    r.close()



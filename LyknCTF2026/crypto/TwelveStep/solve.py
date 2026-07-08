from pwn import *
from math import gcd
from functools import reduce

# Konfigurasi koneksi
HOST = '51.79.140.18'
PORT = 15937

def solve_linear_congruence(a, b, m):
    """Menyelesaikan persamaan ax ≡ b (mod m) bahkan jika gcd(a, m) > 1"""
    g = gcd(a, m)
    if b % g != 0:
        return None  # Tidak ada solusi
    
    # Reduksi persamaan dengan membaginya dengan GCD
    a //= g
    b //= g
    m_prime = m // g
    
    # Sekarang gcd(a, m_prime) pasti 1, aman mencari modular inverse
    try:
        x = (b * pow(a, -1, m_prime)) % m_prime
        # Kembalikan solusi dasar
        return x
    except ValueError:
        return None

def crack_lcg(states):
    # 1. Mencari Modulus (m)
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zero_mods = [d2 * d0 - d1**2 for d0, d1, d2 in zip(diffs, diffs[1:], diffs[2:])]
    m = abs(reduce(gcd, zero_mods))
    
    # Jika m terlalu besar/merupakan kelipatan, kita bisa membersihkannya
    # Namun biasanya m hasil GCD dari banyak sample sudah cukup akurat untuk modulo operasi berikutnya
    
    # 2. Mencari Multiplier (a)
    # Persamaan: diffs[1] ≡ a * diffs[0] (mod m) => a * diffs[0] ≡ diffs[1] (mod m)
    a = None
    for i in range(len(diffs) - 1):
        sol = solve_linear_congruence(diffs[i], diffs[i+1], m)
        if sol is not None:
            a = sol
            # Validasi apakah 'a' ini konsisten untuk diff berikutnya
            if (diffs[i+1] - a * diffs[i]) % m == 0:
                break
                
    if a is None:
        raise Exception("Gagal menemukan nilai 'a' yang valid.")

    # 3. Mencari Increment (c)
    c = (states[1] - states[0] * a) % m
    
    return a, c, m

# Mulai koneksi ke server
r = remote(HOST, PORT)

# Menerima text hingga baris output dimulai
r.recvuntil(b"Here are 12 consecutive outputs:\n")

# Array untuk menyimpan 12 ouput
outputs = []

for i in range(12):
    line = r.recvline().decode().strip()
    val = int(line.split('=')[1].strip())
    outputs.append(val)

print(f"[+] Berhasil mendapatkan 12 output: {outputs}")

# Jalankan fungsi crack LCG yang baru
print("[*] Menghitung parameter LCG (a, c, m)...")
try:
    a, c, m = crack_lcg(outputs)
    print(f"[+] Terpecahkan! \n  a = {a}\n  c = {c}\n  m = {m}")

    # Hitung out[12]
    next_val = (a * outputs[-1] + c) % m
    print(f"[+] Prediksi out[12]: {next_val}")

    # Kirim jawaban ke server
    r.recvuntil(b"out[12] = ")
    r.sendline(str(next_val).encode())

    # Cetak sisa flag yang muncul
    print("[*] Mengirim jawaban dan mengambil flag...")
    print(r.recvall().decode())

except Exception as e:
    print(f"[-] Terjadi kesalahan: {e}")
    r.close()

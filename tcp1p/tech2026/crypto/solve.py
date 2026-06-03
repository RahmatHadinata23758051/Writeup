from pwn import *
import re

# --- Konfigurasi Koneksi ---
HOST = 'gzcli.1pc.tf'
PORT = 32797

def iroot(k, n):
    """Fungsi untuk mencari akar pangkat k dari n secara presisi."""
    u, s = n, n + 1
    while u < s:
        s = u
        t = (k - 1) * s + n // pow(s, k - 1)
        u = t // k
    return s

def solve():
    # Membuat koneksi ke server
    io = remote(HOST, PORT)
    
    log.info("Menerima data dari server...")
    
    # Menerima semua data teks dari server
    data = io.recvuntil(b"Your guess:").decode()
    
    # Parsing menggunakan regular expression agar lebih akurat
    try:
        N = int(re.search(r'N=(\d+)', data).group(1))
        # Mengambil list l dan cts (karena formatnya string Python list, kita bisa gunakan eval)
        l_str = re.search(r'l=(\[.*?\])', data, re.DOTALL).group(1)
        l = eval(l_str)
        
        cts_str = re.search(r'cts=(\[.*?\])', data, re.DOTALL).group(1)
        cts = eval(cts_str)
        
        secret = int(re.search(r'secret=(\d+)', data).group(1))
    except Exception as e:
        log.error(f"Gagal melakukan parsing data: {e}")
        return

    log.success(f"Data berhasil diambil!")
    
    # --- Perhitungan Matematika ---
    # 1. Hitung S = jumlah dari semua l mod N
    S = sum(l) % N
    
    # 2. Konstanta 5^-1 mod N
    inv5 = pow(5, -1, N)
    
    # 3. Hitung M0 = (l[0] - S * inv5)
    # Persamaan: cs[0] = delta * M0 (mod N)
    M0 = (l[0] - S * inv5) % N
    
    # 4. Cari delta^5
    # cts[0] = cs[0]^5 = (delta * M0)^5
    delta_5 = (cts[0] * pow(pow(M0, 5, N), -1, N)) % N
    
    # 5. Cari delta dengan akar pangkat 5
    delta = iroot(5, delta_5)
    log.info(f"Ditemukan delta: {delta}")
    
    # 6. Rekonstruksi semua nilai cs
    cs = []
    for val_l in l:
        cs_i = (delta * (val_l - S * inv5)) % N
        cs.append(cs_i)
        
    # 7. Hitung nilai original (ori)
    # Karena secret = ori ^ c1 ^ c2 ^ ... ^ ck
    # Maka ori = secret ^ c1 ^ c2 ^ ... ^ ck
    ori = secret
    for c in cs:
        ori ^= c
        
    log.success(f"Menemukan nilai ori: {ori}")
    
    # Mengirim jawaban ke server
    io.sendline(str(ori).encode())
    
    # Menampilkan output terakhir (biasanya FLAG)
    result = io.recvall().decode()
    print("\n" + "="*20 + " HASIL " + "="*20)
    print(result)
    print("="*47)

if __name__ == "__main__":
    solve()

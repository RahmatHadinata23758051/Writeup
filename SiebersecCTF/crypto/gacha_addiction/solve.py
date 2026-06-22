from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Konfigurasi koneksi remote ke server target
p = remote('chal.sieberr.live', 20000)

# 1. Parsing Nilai n, e, dan Ciphertext dari Banner Utama
p.recvuntil(b'n = ')
n = int(p.recvline().strip())
p.recvuntil(b'e = ')
e = int(p.recvline().strip())
p.recvuntil(b'ciphertext = ')
ciphertext = int(p.recvline().strip())

# Perbaikan pembungkusan str() agar tidak memicu TypeError
log.info(f"Mengambil Public Key N: {str(n)[:20]}... (Truncated)")
log.info(f"Mengambil Ciphertext: {str(ciphertext)[:20]}... (Truncated)")

# Nilai kupon target
coupon = b'Winning5050sFORFREE'
M = bytes_to_long(coupon)

# 2. Proses RSA Blinding (Menyamarkan Pesan Kupon)
X = 2
M_prime = (M * pow(X, e, n)) % n

# Kirim Opsi 1 untuk menandatangani pesan samaran
p.sendlineafter(b'What will your choice be(1/2/3/4): ', b'1')
p.sendlineafter(b'Please input the message to sign: ', str(M_prime).encode())
p.recvuntil(b'your signed message is: ')
S_prime = int(p.recvline().strip())

# Proses Unblinding (Mendapatkan Tanda Tangan Kupon Asli)
X_inv = pow(X, -1, n)
S = (S_prime * X_inv) % n

# 3. Klaim Kupon Tambahan (Opsi 2)
p.sendlineafter(b'What will your choice be(1/2/3/4): ', b'2')
p.sendlineafter(b'please input your signed message: ', str(S).encode())
log.success("Kupon berhasil diklaim! Total Pulls menjadi 100.")

# 4. Melakukan Gacha untuk Mencapai Hard Pity (91 Kali Eksekusi)
log.info("Sedang melakukan gacha sebanyak 91 kali untuk memicu Hard Pity...")
for i in range(91):
    p.sendlineafter(b'What will your choice be(1/2/3/4): ', b'3')

# Parsing nilai p asli yang keluar saat hard pity tercapai
p.recvuntil(b'p = ')
p_factor = int(p.recvline().strip())
log.success(f"Hard Pity Tercapai! Nilai p didapatkan: {str(p_factor)[:20]}...")

# 5. Memfaktorkan RSA & Mendekripsi Flag
q_factor = n // p_factor
phi = (p_factor - 1) * (q_factor - 1)
d = pow(e, -1, phi)

# Dekripsi ciphertext menjadi byte flag asli
flag_long = pow(ciphertext, d, n)
flag = long_to_bytes(flag_long)

log.success(f"Flag Berhasil Ditemukan: {flag.decode()}")

p.close()

from pwn import *
import hashlib
from Crypto.Util.number import inverse
from ecdsa import SigningKey, NIST256p, SECP256k1

HOST = 'chal.thjcc.org'
PORT = 12001

def solve():
    io = remote(HOST, PORT)
    
    # 1. Parsing data dari server
    io.recvuntil(b"PUB ")
    pub_x_hex, pub_y_hex = io.recvline().decode().strip().split()
    
    io.recvuntil(b"SIG ")
    msg1_hex, r1_hex, s1_hex = io.recvline().decode().strip().split()
    
    io.recvuntil(b"SIG ")
    msg2_hex, r2_hex, s2_hex = io.recvline().decode().strip().split()
    
    io.recvuntil(b"TARGET ")
    target_hex = io.recvline().decode().strip()
    
    # Konversi ke Integer / Bytes
    r = int(r1_hex, 16)
    s1 = int(s1_hex, 16)
    s2 = int(s2_hex, 16)
    pub_x = int(pub_x_hex, 16)
    pub_y = int(pub_y_hex, 16)
    
    msg1 = bytes.fromhex(msg1_hex)
    msg2 = bytes.fromhex(msg2_hex)
    target_msg = bytes.fromhex(target_hex)
    
    z1 = int.from_bytes(hashlib.sha256(msg1).digest(), 'big')
    z2 = int.from_bytes(hashlib.sha256(msg2).digest(), 'big')
    
    log.info("Mencari Kurva yang tepat dan mengekstrak Private Key...")
    
    correct_sk = None
    
    # 2. Coba kedua Kurva secara otomatis
    for curve_name, CURVE in [("NIST256p", NIST256p), ("SECP256k1", SECP256k1)]:
        n = CURVE.order
        try:
            # Mencari k dan d
            k = ((z1 - z2) * inverse(s1 - s2, n)) % n
            d = ((s1 * k - z1) * inverse(r, n)) % n
            
            # Buat instance key dan derive Public Key-nya
            sk = SigningKey.from_secret_exponent(d, curve=CURVE)
            vk = sk.get_verifying_key()
            
            # VERIFIKASI: Apakah d kita menghasilkan PUB yang sama dengan server?
            if vk.pubkey.point.x() == pub_x and vk.pubkey.point.y() == pub_y:
                log.success(f"Kurva yang benar ditemukan: {curve_name}")
                log.success(f"Private Key tervalidasi 100% Benar: {hex(d)}")
                correct_sk = sk
                break
        except Exception as e:
            continue
            
    if not correct_sk:
        log.error("Gagal mengekstrak Private Key. Periksa metode perhitungan.")
        return

    # 3. Buat Tanda Tangan untuk TARGET
    sig_target = correct_sk.sign_deterministic(target_msg, hashfunc=hashlib.sha256)
    r_target = sig_target[:32].hex()
    s_target = sig_target[32:].hex()
    
    # 4. Kirim Payload
    # Default kita coba pisah dengan spasi
    payload = f"{r_target} {s_target}".encode()
    log.info(f"Mengirim payload: {payload}")
    
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    solve()


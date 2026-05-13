from Crypto.Util.number import inverse

def solve_ecdsa_nonce_reuse():
    # Parameter Kurva secp256k1 (Order n)
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    # Data dari output.txt
    z1 = 0x3f12c87a7847acffea7cbbda8e65cfbbcaa987124424861b754773f48f9099cf
    r  = 0xf1f9868668a5add66dd96d6712eab1fe6a94da480e2863a1671864b927b29494
    s1 = 0xf6b890ba847741d34aace32aec779d81c41006d6b710e203deedb8442ff613f2

    z2 = 0x45e656fff1a82884c860a495cb39c1e8634992e4e10c21887d64250c39e3c9bd
    s2 = 0x8d30c4a40494387ed709bdd069c059e6303f8e0087646b69ea5d4933598f5a8d

    print("[*] Menghitung k (nonce)...")
    # k = (z1 - z2) * inv(s1 - s2) mod n
    k = ((z1 - z2) * inverse(s1 - s2, n)) % n
    
    print("[*] Menghitung private key (d)...")
    # d = (s1 * k - z1) * inv(r) mod n
    d = ((s1 * k - z1) * inverse(r, n)) % n

    print("-" * 20)
    print(f"Private Key (Decimal): {d}")
    print(f"Private Key (Hex): {hex(d)}")
    
    # Mencoba decode ke string jika flag ada di dalam key
    try:
        flag = bytes.fromhex(hex(d)[2:]).decode('utf-8')
        print(f"Flag (String): {flag}")
    except:
        pass

if __name__ == "__main__":
    solve_ecdsa_nonce_reuse()

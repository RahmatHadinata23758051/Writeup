# solve.py
n  = 77858147671482407634775491427040805492076980205563716402246138065521424847352748333947251695438000383243920464095595462728641255858191058453473003730294210301598211003700846609849972322991848231552293626273416217314260783103263284010287945923693495357051277469279606933481196189861065420108007616409643776013
e1 = 111
c1 = 18223062994297197653234717982144573569773880742037431830544439999553795195125626505331124696776901462144736197874973901036255517289372748992723223498997000791202721932133429983002886149582411413191392795467958837528737663052532838054771927153786855378458367115645172309532793321789113491998416988084430368204
e2 = 39
c2 = 76348018939213272185590808359388052466934484463344890672730708364972146374564171707212345714373329559752891016395108524379113926994557487020813255966324592722174363480000800186421273525315732093443649340134436194571066648858343990234218106682132787231616400778754021668597178594337592606373176172822415096792

# Extended Euclidean Algorithm
def xgcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = xgcd(b % a, a)
    return g, x - (b // a) * y, y

# Fungsi Binary Search untuk integer root (K-th root)
def iroot(k, n_val):
    u, s = n_val, n_val + 1
    while u < s:
        s = u
        t = (k - 1) * s + n_val // pow(s, k - 1)
        u = t // k
    return s

def solve():
    print("[*] Memulai Modified Common Modulus Attack...")
    g, a, b = xgcd(e1, e2)
    print(f"[*] gcd({e1}, {e2}) = {g}")
    print(f"[*] Koefisien ditemukan: a = {a}, b = {b}")

    # Menghitung C = (c1^a * c2^b) mod n
    # Python 3.8+ otomatis melakukan modular inverse jika nilai pangkat (a/b) bernilai negatif.
    C = (pow(c1, a, n) * pow(c2, b, n)) % n
    print(f"[*] Berhasil menghitung m^{g} mod n")

    # Pencarian akar pangkat (kemungkinan m^3 < n, namun kita loop jaga-jaga jika wraparound modulus)
    for k in range(100):
        val = C + k * n
        m = iroot(g, val)
        
        # Cek jika nilai hasil perhitungan valid 
        if pow(m, g) == val:
            print(f"[*] Integer root yang persis ditemukan pada k={k}!")
            
            # Konversi Integer ke Bytes ASCII untuk mendapatkan flag
            flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            try:
                flag_text = flag_bytes.decode('utf-8')
                print(f"\n[+] FLAG: {flag_text}")
                break
            except UnicodeDecodeError:
                pass

if __name__ == '__main__':
    solve()

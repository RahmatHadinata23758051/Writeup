import urllib.request
import json
import math
from Crypto.Util.number import inverse, long_to_bytes

n = 62682216990035535414283237955614406493486258273076495832619690617581399538236582733286582178140321635624802660210721998730275248454086168837416782088550491400416319284287815150726740331977962842388233786083212916620371826297302047969193232160668421600986861080824486495143695469089008397024327125212947684843
e = 65537
c = 41024268756704469337209786652193690890811149688733418732013754564209667759334906563389075973052952807352876454272575695748298849360747901013416234315682754403926508012342496824014970774417277067925685998503459215288795844028250361334123045534438982674518957947709411579479137377945816515652458197367030858483

def caesar_decrypt(text, shift):
    result = []
    for char in text:
        if char.isalpha():
            base = ord('a') if char.islower() else ord('A')
            result.append(chr((ord(char) - base - shift) % 26 + base))
        else:
            result.append(char)
    return ''.join(result)

def fermat_factor(n):
    a = math.isqrt(n) + 1
    b2 = a*a - n
    limit = 1000000
    while not (math.isqrt(b2)**2 == b2) and limit > 0:
        a += 1
        b2 = a*a - n
        limit -= 1
    if math.isqrt(b2)**2 == b2:
        return a - math.isqrt(b2), a + math.isqrt(b2)
    return None, None

def solve():
    print("[*] Melakukan Fermat Factorization (mencari jarak p & q yang sempit)...")
    p, q = fermat_factor(n)
    
    factors = []
    if p and q:
        print(f"[+] Fermat berhasil menjebol n!")
        factors = [p, q]
    else:
        print("[-] Fermat gagal. Mengambil intelijen dari Factordb...")
        try:
            req = urllib.request.urlopen(f"http://factordb.com/api?query={n}")
            data = json.loads(req.read().decode())
            if data['status'] in ('FF', 'CF'):
                print("[+] Faktor ditemukan di Factordb!")
                for f_str, exp in data['factors']:
                    factors.extend([int(f_str)] * exp)
            else:
                print("[!] Factordb belum memiliki faktor untuk n ini. Butuh serangan lain.")
                return
        except Exception as ex:
            print(f"[!] Error jaringan Factordb: {ex}")
            return
            
    # Menghitung fungsi Totient Euler (phi) yang mendukung Multi-Prime RSA
    phi = 1
    unique_factors = set(factors)
    for f in unique_factors:
        phi *= (f ** (factors.count(f) - 1)) * (f - 1)
        
    print("[*] Menghitung Private Key (d) dan mendekripsi RSA...")
    d = inverse(e, phi)
    m = pow(c, d, n)
    
    shifted_flag = long_to_bytes(m).decode(errors='ignore')
    print(f"[+] Teks terdekripsi (Masih dienkripsi Caesar oleh Vikram): {shifted_flag}")
    
    print("[*] Memutar balik Caesar Cipher (shift = -6)...")
    flag = caesar_decrypt(shifted_flag, 6) # len("vikram") = 6
    print(f"\n[!] FLAG DITEMUKAN: {flag}")

if __name__ == '__main__':
    solve()

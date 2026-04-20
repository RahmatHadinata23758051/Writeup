import base64
import requests
import math
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse

# Data dari file rsa.txt
b64_cipher = "aOCmih7+sJ6kVC5cvdytyi1OILZnUMU3tC1IfXJpvPMtMMESjppgeHm4ync7orf/Gm9LDeGeWFttxlmWMWLYbiz258fbVzvoSCj92+2kWKY8UN8yYcKPo7IoC/NmZX4dRgZ9NBopkf794ylGJgIIamzUR2Sauinul5YSJKAt0s6w3OOD40mmJDhRn5D0KuYiPHZDQ33xakTfbstxcTpB3jtA01Rt6iXydiXotarTjjplrdc3359bHGyLvzRtHPlExAYSdJfc63WAC4vFbmg+/x24E969ItexAo2JK1oztz8tUHmrDxsBu/07SXFx2PYbDkGPzJBkYKT/2ThntFEfTA=="
n = 18271752466870180127745800868708214630162281586246824926034232332196351776561071950037425807823961949825871587999632822002545598857069391130795394202584764494207030362917447457268736832607015087954459047881817775038313528023934958504556651502169601424341939024000029258765144167071321184423165780495670199483967570271688266234095972607310527103298638983648876977256819771874170373215698104824112235358691388513829839627733460293223417818020170986408426995425094909307732676356022654099726165321395889520207421801010493399031785063732178161886471855433898402905218076018155390995627562100053780658426580765757127671281
e = 65537 # Asumsi e menggunakan default pada umumnya

def decrypt_rsa(p, q, c, e, n):
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    m = pow(c, d, n)
    raw_bytes = long_to_bytes(m)
    
    # Cek apakah format menggunakan PKCS#1 v1.5 (dimulai dengan \x02)
    if raw_bytes.startswith(b'\x02'):
        # Pisahkan berdasarkan byte \x00 pertama yang ditemui
        try:
            # Index 1 adalah pesan asli setelah \x00 pemisah
            clean_msg = raw_bytes.split(b'\x00', 1)[1].decode('utf-8', errors='ignore')
            return clean_msg
        except IndexError:
            pass # Lanjut ke return raw_bytes jika gagal dipisah
            
    # Jika tidak pakai padding atau bukan teks standar, kembalikan byte utuh
    try:
        return raw_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return raw_bytes

def fermat_factorization(n):
    print("[*] Mencoba serangan Fermat Factorization (jika p dan q berdekatan)...")
    a = math.isqrt(n)
    
    # PERBAIKAN: Pastikan a dibulatkan ke atas agar a^2 > n
    if a * a < n:
        a += 1
        
    b2 = a * a - n
    b = math.isqrt(b2)
    count = 0
    
    while b * b != b2:
        a += 1
        b2 = a * a - n
        b = math.isqrt(b2)
        count += 1
        
        # Limit iterasi agar tidak berjalan selamanya
        if count > 5000000: 
            print("[-] Proses Fermat terlalu lama, dihentikan. Jarak p dan q terlalu jauh.")
            return None, None
            
    print("[+] Fermat Factorization berhasil!")
    return a - b, a + b

def check_factordb(n):
    print("[*] Mencari faktor p dan q di FactorDB...")
    try:
        res = requests.get(f"http://factordb.com/api?query={n}").json()
        if res.get('status') == 'FF':
            factors = res.get('factors')
            if len(factors) == 2:
                p = int(factors[0][0])
                q = int(factors[1][0])
                print("[+] Mantap! Faktor ditemukan di FactorDB.")
                return p, q
        print("[-] N belum difaktorkan secara penuh di FactorDB.")
    except Exception as ex:
        print(f"[-] Terjadi error saat mengakses FactorDB: {ex}")
    return None, None



def main():
    print("[*] Melakukan dekode Base64 pada ciphertext...")
    c = bytes_to_long(base64.b64decode(b64_cipher))
    
    # 1. Coba FactorDB
    p, q = check_factordb(n)
    
    # 2. Coba Fermat jika FactorDB gagal
    if not p:
        p, q = fermat_factorization(n)
        
    if p and q:
        print(f"[*] Menghitung nilai d (Private Key) dan mendekripsi pesan...")
        flag = decrypt_rsa(p, q, c, e, n)
        print("\n[+] Sukses! Flag berhasil di-decrypt:\n")
        print(flag)
    else:
        print("\n[-] Gagal memfaktorkan N. Kamu mungkin perlu tools eksternal (seperti Yafu) atau memeriksa kemungkinan vulnerabilitas lain.")

if __name__ == "__main__":
    main()

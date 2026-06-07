from Crypto.Util.number import long_to_bytes, inverse
import math

# Data dari output.txt
n = 5216528649875826746373274623709911527907930166016984164533272620692599945581004244622652640509156720922738730017397970929856922904389747851230187154375161
e = 65537
ct = 1769561623039780835813534940346776273175000099891521520378974868184264352157081415449182707720490727295376770632579942515719007563037959358184643750159804
s = 1220125626995232022797746032625764407124557835619605483513423136472322667738087444211114063128377505634674691423794338554652601901132201128484832327199237
spz = 2144640816488997996880355081959057062388718728036090601522167913668193535885347340870230640225749237841665830391473546117213483723045473075426308182703379

print("[*] Menghitung faktor q menggunakan Fault Attack...")
# Mencari gcd dari selisih spz dan s dengan n
q = math.gcd(abs(spz - s), n)

# Memastikan q adalah faktor yang valid (bukan 1 dan bukan n)
if q > 1 and q < n:
    p = n // q
    print(f"[+] Faktor ditemukan!")
    print(f"    p = {p}")
    print(f"    q = {q}")
    
    # Cara Tercepat: Karena s adalah signature valid (s = m^d mod n),
    # kita bisa langsung mendapatkan m dengan menghitung s^e mod n.
    print("\n[*] Mendekripsi flag langsung dari signature (s)...")
    m = pow(s, e, n)
    
    flag = long_to_bytes(m)
    print(f"\n[+] FLAG: {flag.decode('utf-8', errors='ignore')}")
else:
    print("[-] Gagal menemukan faktor. Periksa kembali input data.")

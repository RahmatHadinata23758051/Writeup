import requests
import json
from Crypto.Util.number import long_to_bytes, inverse

# Data dari cipher.txt
n = 1838728184695871659965012189610295270665548277743170978477811033285784122401925676473091945840761097230358112793269159175523352904583082710661432383586054756989336914086267086282261815103722709523091728221623957702900301124878651337623985822069898206814203104595126969177996998431362486639056055349584704987009282334768918035439577276111964948640918939110460050009666129310410354538866707598179087805495281114570426986316731323553476567423888230008826031200982236779868885532826970566394829392616541380902228086261386950569625906913931124943742837569848435973408085296846480875452543065548991901360785409742687475380901
e = 65537
c = 789545866347439920710445699573254153680505782482756993843356750980220383218945019393920653402758903298961579834860269864723264413119811332414724945575026435841383953497751702639326431362640371689770093794458588005697099946848826383795374803739641872724604053825535708973930008279621031161769534300009342429497648284351686580075106498405528267107474469195434707074304510989598742806146185572482356930204310432254906432917437583495091279111823135243990442691262246628875356373201376815813508297361384609829242597557658901077250276402989705573487361905198470585599080421232703134641467570445229006472956517079740557680862

print("[*] Mencoba memfaktorkan N menggunakan Factordb...")

try:
    # Request ke API Factordb
    url = f"https://factordb.com/api?query={n}"
    response = requests.get(url, timeout=10)
    data = response.json()
    
    if data['status'] == 'FF' or data['status'] == 'CF': # Fully Factored atau Partially Factored
        factors = []
        for factor_info in data['factors']:
            value = int(factor_info[0])
            count = factor_info[1]
            for _ in range(count):
                factors.append(value)
        
        print(f"[+] Berhasil! Ditemukan {len(factors)} faktor.")
        
        # Jika N terbagi menjadi 2 faktor prima (p dan q)
        if len(factors) == 2:
            p, q = factors[0], factors[1]
            phi = (p - 1) * (q - 1)
            d = inverse(e, phi)
            m = pow(c, d, n)
            flag = long_to_bytes(m)
            print(f"\n[+] FLAG: {flag.decode(errors='ignore')}")
        else:
            # Jika faktornya multi-prime (lebih dari 2)
            print("[*] Menghitung Multi-Prime RSA...")
            phi = n
            # Rumus phi untuk multi-prime berkekuatan 1: phi = n * prod(1 - 1/p)
            # Karena unik, kita pakai cara perkalian (p-1)*(q-1)*(r-1)...
            phi_calc = 1
            for p in set(factors):
                phi_calc *= (p - 1)
            
            d = inverse(e, phi_calc)
            m = pow(c, d, n)
            flag = long_to_bytes(m)
            print(f"\n[+] FLAG: {flag.decode(errors='ignore')}")
            
    else:
        print("[-] N tidak ditemukan/belum difaktorkan di Factordb.")
        print("[*] Mencoba alternatif serangan: Wiener's Attack atau Fermat...")
        # Tambahkan fungsi eksekusi lokal di sini jika Factordb gagal
        
except Exception as e_err:
    print(f"[-] Terjadi kesalahan saat menghubungi Factordb: {e_err}")

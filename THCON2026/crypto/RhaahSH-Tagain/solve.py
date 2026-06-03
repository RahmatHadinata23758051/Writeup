import zipfile
import re

def solve():
    print("[*] Mengabaikan RSA, mari kita bongkar isi perut Last_Orders.xlsx...")
    
    unique_pans = set()
    
    try:
        # Buka xlsx sebagai format aslinya (ZIP Archive)
        with zipfile.ZipFile("Last_Orders.xlsx", "r") as z:
            for filename in z.namelist():
                if filename.endswith(".xml"):
                    data = z.read(filename).decode('utf-8', errors='ignore')
                    
                    # Cari semua rentetan angka dengan panjang 15 sampai 19 digit
                    # (Format standar nomor kartu kredit / PAN)
                    matches = re.findall(r'\b\d{15,19}\b', data)
                    
                    if matches:
                        for m in matches:
                            unique_pans.add(int(m))
                            print(f"    [+] Nemu angka raw di {filename} -> {m}")
                            
        print("\n[=========================================]")
        if unique_pans:
            print(f"[+] Total PAN raw unik yang ditemukan: {len(unique_pans)}")
            print(f"[+] FLAG: THC{{{sum(unique_pans)}}}")
        else:
            print("[-] Zonk bro. Gak ada data raw. Banknya ternyata jago IT.")
            
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    solve()

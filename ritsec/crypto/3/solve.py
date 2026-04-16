import itertools

def solve():
    alphabet = r"""G!{Qq)EPU-M7yNAKnF%fS=\Z?;+.T2/8Lx65'@*VBw,#k:|~Dr`eOa9H"hb>3^<Jp}[&$iXogzl4vWu(tsc]1YmC_RI0jd"""
    
    m1, m2, m3 = 95, 37, 19
    s1, s2, s3 = 11, 29, 7

    target_idx = [alphabet.find('R'), alphabet.find('S'), alphabet.find('{')]
    signs_list = list(itertools.product([1, -1], repeat=3))

    print("[*] Memulai pencarian komprehensif (Mengabaikan degenerate multiplier)...")
    
    found_count = 0
    
    # Mulai dari 2! Multiplier 1 itu mesin rusak.
    for a1 in range(2, m1):
        for a2 in range(2, m2):
            for a3 in range(2, m3):
                
                # Langkah 1
                x1_1 = (s1 * a1) % m1
                x2_1 = (s2 * a2) % m2
                x3_1 = (s3 * a3) % m3
                
                # Langkah 2
                x1_2 = (x1_1 * a1) % m1
                x2_2 = (x2_1 * a2) % m2
                x3_2 = (x3_1 * a3) % m3
                
                # Langkah 3
                x1_3 = (x1_2 * a1) % m1
                x2_3 = (x2_2 * a2) % m2
                x3_3 = (x3_2 * a3) % m3
                
                for sgn1, sgn2, sgn3 in signs_list:
                    for offset in [0, -1, 1]: 
                        i1 = (sgn1*x1_1 + sgn2*x2_1 + sgn3*x3_1 + offset) % 94
                        if i1 != target_idx[0]: continue
                        
                        i2 = (sgn1*x1_2 + sgn2*x2_2 + sgn3*x3_2 + offset) % 94
                        if i2 != target_idx[1]: continue
                        
                        i3 = (sgn1*x1_3 + sgn2*x2_3 + sgn3*x3_3 + offset) % 94
                        if i3 != target_idx[2]: continue
                        
                        found_count += 1
                        cx1, cx2, cx3 = s1, s2, s3
                        flag = ""
                        # Cetak 40 karakter saja agar layar tidak penuh
                        for _ in range(40):
                            cx1 = (cx1 * a1) % m1
                            cx2 = (cx2 * a2) % m2
                            cx3 = (cx3 * a3) % m3
                            
                            idx = (sgn1*cx1 + sgn2*cx2 + sgn3*cx3 + offset) % 94
                            flag += alphabet[idx]
                            
                        print(f"\n[+] KANDIDAT #{found_count}")
                        print(f"    a1={a1}, a2={a2}, a3={a3} | Tanda: ({sgn1}, {sgn2}, {sgn3})")
                        print(f"--> FLAG: {flag}...")

    if found_count == 0:
        print("\n[!] Gagal. Tidak ada satupun yang cocok.")
    else:
        print(f"\n[*] Selesai. Ditemukan {found_count} kandidat flag. Silakan pilih yang bisa dibaca!")

if __name__ == "__main__":
    solve()

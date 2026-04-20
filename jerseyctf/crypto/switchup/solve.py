import sys
from itertools import permutations, product

# --- DATA TARGET ---
WIRINGS = {
    '1': "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
    '2': "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    '3': "BDFHJLCPRTXVZNYEIWGAKMUSQO"
}
NOTCHES = {'1': 16, '2': 4, '3': 21} # Posisi Notch: Q=16, E=4, V=21
REFLECTOR = [ord(c)-65 for c in "LCBRWPZUMNXAIJQFODYVHTEKSG"]

PT = "STARTTRANSMISSIONEXPERIENCINGTECHNICALDIFFICULTIESBUTWILLTRANSMITMESSAGEINFIFTEENMINUTES"
CT = "MHNHBXLOOPPZLTUNMQQAZVEJTUMJLAULSLYPVKWEKYKEKFGNZFFAZPQFCSKHFGOODTKVZTHWURNOJKGQYVGBAGOQ"
TARGET_CT = "RMZHFXDZUDDWWZADXWOBFKXKTWRCEVRKCVSUTCJNHLYUXGEUCAUIBBJGVTEWSRWDFEPRUYPXTXPLAQGFCXJPTMZFEBJVBDIVSIVHCNHMKBGDWNOOQLYNAOTOHLPUZODL"

# Konversi string ke array integer (0-25) agar super cepat
pt_ints = [ord(c)-65 for c in PT]
ct_ints = [ord(c)-65 for c in CT]
target_ints = [ord(c)-65 for c in TARGET_CT]

w_fwd, w_rev = {}, {}
for k, v in WIRINGS.items():
    w_fwd[k] = [ord(c)-65 for c in v]
    rev = [0]*26
    for i, c in enumerate(v): rev[ord(c)-65] = i
    w_rev[k] = rev

def solve():
    print("[*] Memulai Ultimate Enigma KPA (Mencari Ring Settings / Notch Damage)...")
    orders = list(permutations(['1', '2', '3']))
    
    for order in orders:
        w1, w2, w3 = w_fwd[order[0]], w_fwd[order[1]], w_fwd[order[2]]
        r1, r2, r3 = w_rev[order[0]], w_rev[order[1]], w_rev[order[2]]
        n1, n2, n3 = NOTCHES[order[0]], NOTCHES[order[1]], NOTCHES[order[2]]
        
        # TAHAP 1: Cari Effective Offsets yang valid HANYA untuk huruf pertama (Super Cepat!)
        valid_eff = []
        for e1, e2, e3 in product(range(26), repeat=3):
            c = pt_ints[0]
            c = (w3[(c + e3) % 26] - e3) % 26
            c = (w2[(c + e2) % 26] - e2) % 26
            c = (w1[(c + e1) % 26] - e1) % 26
            c = REFLECTOR[c]
            c = (r1[(c + e1) % 26] - e1) % 26
            c = (r2[(c + e2) % 26] - e2) % 26
            c = (r3[(c + e3) % 26] - e3) % 26
            
            if c == ct_ints[0]:
                valid_eff.append((e1, e2, e3))
                
        # TAHAP 2: Tes Ring Settings hanya pada jalur yang masuk akal
        for e1, e2, e3 in valid_eff:
            for ring2, ring3 in product(range(26), repeat=2):
                ring1 = 0 # Rotor paling lambat jarang berputar, ring1 diasumsikan statis
                
                # Posisi rotor SAAT huruf pertama diproses
                p1_start = e1
                p2_start = (e2 + ring2) % 26
                p3_start = (e3 + ring3) % 26
                
                p1, p2, p3 = p1_start, p2_start, p3_start
                match = True
                
                # Cek sisa string
                for i in range(1, len(pt_ints)):
                    c_in = pt_ints[i]
                    
                    # Stepping Mekanik
                    s1 = s2 = s3 = False
                    s3 = True
                    if p2 == n2: s1 = s2 = True
                    elif p3 == n3: s2 = True
                    if s1: p1 = (p1 + 1) % 26
                    if s2: p2 = (p2 + 1) % 26
                    if s3: p3 = (p3 + 1) % 26
                    
                    curr_e1 = (p1 - ring1) % 26
                    curr_e2 = (p2 - ring2) % 26
                    curr_e3 = (p3 - ring3) % 26
                    
                    enc = (w3[(c_in + curr_e3) % 26] - curr_e3) % 26
                    enc = (w2[(enc + curr_e2) % 26] - curr_e2) % 26
                    enc = (w1[(enc + curr_e1) % 26] - curr_e1) % 26
                    enc = REFLECTOR[enc]
                    enc = (r1[(enc + curr_e1) % 26] - curr_e1) % 26
                    enc = (r2[(enc + curr_e2) % 26] - curr_e2) % 26
                    enc = (r3[(enc + curr_e3) % 26] - curr_e3) % 26
                    
                    if enc != ct_ints[i]:
                        match = False
                        break
                        
                if match:
                    print(f"\n[+] BINGO! Kerusakan Mesin Terpecahkan (Ring/Notch Shifted):")
                    print(f"    Urutan Rotor  : {order}")
                    
                    # Kalkulasi ulang posisi inisial sebelum mesin menyala (reverse step pertama)
                    init_p3 = (p3_start - 1) % 26
                    init_p2 = (p2_start - 1) % 26 if init_p3 == n3 else p2_start
                    init_p1 = (p1_start - 1) % 26 if (init_p2 == n2 and init_p3 == n3) else p1_start
                    
                    print(f"    Ring Settings : {chr(ring1+65)}{chr(ring2+65)}{chr(ring3+65)}")
                    print(f"    Posisi Awal   : {chr(init_p1+65)}{chr(init_p2+65)}{chr(init_p3+65)}")
                    
                    # Dekripsi Target!
                    print("\n[*] Menjalankan Dekripsi Akhir...")
                    p1, p2, p3 = init_p1, init_p2, init_p3
                    out = []
                    
                    for c_target in target_ints:
                        s1 = s2 = s3 = False
                        s3 = True
                        if p2 == n2: s1 = s2 = True
                        elif p3 == n3: s2 = True
                        if s1: p1 = (p1 + 1) % 26
                        if s2: p2 = (p2 + 1) % 26
                        if s3: p3 = (p3 + 1) % 26
                        
                        curr_e1 = (p1 - ring1) % 26
                        curr_e2 = (p2 - ring2) % 26
                        curr_e3 = (p3 - ring3) % 26
                        
                        dec = (w3[(c_target + curr_e3) % 26] - curr_e3) % 26
                        dec = (w2[(dec + curr_e2) % 26] - curr_e2) % 26
                        dec = (w1[(dec + curr_e1) % 26] - curr_e1) % 26
                        dec = REFLECTOR[dec]
                        dec = (r1[(dec + curr_e1) % 26] - curr_e1) % 26
                        dec = (r2[(dec + curr_e2) % 26] - curr_e2) % 26
                        dec = (r3[(dec + curr_e3) % 26] - curr_e3) % 26
                        
                        out.append(chr(dec + 65))
                        
                    print("\n[+] PESAN RAHASIA (DECRYPTED):")
                    print("="*60)
                    print("".join(out))
                    print("="*60)
                    return

if __name__ == '__main__':
    solve()

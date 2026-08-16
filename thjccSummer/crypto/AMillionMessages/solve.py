import socket
import sys
from Crypto.Util.number import long_to_bytes

HOST = 'chal.thjcc.org'
PORT = 12003

def ceil_div(a, b):
    return (a + b - 1) // b

def do_attack():
    print(f"[*] Menyambungkan ke {HOST}:{PORT}...")
    
    # Menggunakan TCP Socket murni agar I/O ultra-ringan tanpa memori bocor
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    
    # Membuat objek file-like untuk membaca & menulis per baris
    f = sock.makefile('rw', buffering=1) 
    
    try:
        # Membaca N, E, C dari server
        line_N = f.readline().strip()
        N = int(line_N.split(' ')[1], 16)
        
        line_E = f.readline().strip()
        E = int(line_E.split(' ')[1], 16)
        
        line_C = f.readline().strip()
        C = int(line_C.split(' ')[1], 16)
        
        print("[+] Parameter berhasil didapatkan!")
        k = (N.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))
        
        queries = 0
        def oracle(c_test):
            nonlocal queries
            queries += 1
            
            if queries % 1000 == 0:
                print(f"[*] Jumlah query ke server sejauh ini: {queries} ...")
                
            # Kirim payload format 128 karakter hex + newline
            payload = hex(c_test)[2:].zfill(128) + '\n'
            f.write(payload)
            
            res = f.readline().strip()
            if not res:
                print("\n[-] Server memutus koneksi!")
                sys.exit(1)
            
            if "BAD" in res:
                return False
            return True

        print("\n[*] Memulai Bleichenbacher's 1998 Padding Oracle Attack...")
        print("[*] Versi Socket (Ultra-Ringan) - Bebas OOM Killer.")
        
        M = [(2 * B, 3 * B - 1)]
        i = 1
        s_val = 1
        
        while True:
            if i == 1:
                print("[*] Step 2a: Mencari s1 awal (Sekitar 30k-70k query)...")
                s_val = ceil_div(N, 3 * B)
                while True:
                    c_test = (C * pow(s_val, E, N)) % N
                    if oracle(c_test):
                        break
                    s_val += 1
                print(f"\n[+] s1 berhasil ditemukan: {s_val}")
                
            elif len(M) >= 2:
                s_val += 1
                while True:
                    c_test = (C * pow(s_val, E, N)) % N
                    if oracle(c_test):
                        break
                    s_val += 1
                    
            elif len(M) == 1:
                a, b = M[0]
                if a == b:
                    break # Plaintext ditemukan!
                
                r_i = ceil_div(2 * (b * s_val - 2 * B), N)
                found = False
                while not found:
                    s_min = ceil_div(2 * B + r_i * N, b)
                    s_max = (3 * B - 1 + r_i * N) // a
                    for s_test in range(s_min, s_max + 1):
                        c_test = (C * pow(s_test, E, N)) % N
                        if oracle(c_test):
                            s_val = s_test
                            found = True
                            break
                    if not found:
                        r_i += 1
                        
            # Step 3: Narrowing the set of solutions (Penyempitan)
            M_new = []
            for a, b in M:
                r_min = ceil_div(a * s_val - 3 * B + 1, N)
                r_max = (b * s_val - 2 * B) // N
                for r_val in range(r_min, r_max + 1):
                    lower = max(a, ceil_div(2 * B + r_val * N, s_val))
                    upper = min(b, (3 * B - 1 + r_val * N) // s_val)
                    if lower <= upper:
                        M_new.append((lower, upper))
                        
            # Merge interval yang tumpang tindih
            M_new.sort()
            M_merged = []
            for interval in M_new:
                if not M_merged:
                    M_merged.append(interval)
                else:
                    last = M_merged[-1]
                    if interval[0] <= last[1] + 1:
                        M_merged[-1] = (last[0], max(last[1], interval[1]))
                    else:
                        M_merged.append(interval)
            M = M_merged
            
            # Cek status penemuan flag
            if len(M) == 1:
                a, b = M[0]
                bit_diff = (b - a).bit_length()
                print(f"[*] Lebar tebakan tersisa mengerucut: {bit_diff} bits")
                if a == b:
                    print("\n[+] Plaintext berhasil dikalkulasi secara matematis!")
                    break
                    
            i += 1

        # Format Flag PKCS#1 v1.5
        m = M[0][0]
        raw_bytes = long_to_bytes(m)
        print(f"\nRaw Decrypted Bytes: {raw_bytes}")
        
        if b'\x00' in raw_bytes[2:]:
            flag = raw_bytes[raw_bytes.index(b'\x00', 2) + 1:]
            print(f"\n🚩 FLAG: {flag.decode('utf-8', errors='ignore')}")
        else:
            print("[-] Gagal menemukan separator padding. String mentah:")
            print(raw_bytes.decode('utf-8', errors='ignore'))
            
    except Exception as e:
        print(f"\n[!] Error tak terduga: {e}")
    finally:
        sock.close()

if __name__ == '__main__':
    do_attack()

import json
import socket
from py_ecc.bn128 import FQ, multiply, add as g1_add
from challenge_params import ALPHA_G1, BETA_G2, CURVE_ORDER, GAMMA_ABC_G1, GAMMA, DELTA

def parse_int(v):
    return int(v, 0) if isinstance(v, str) else v

def parse_g1(obj):
    return (FQ(parse_int(obj["x"])), FQ(parse_int(obj["y"])))

# Parsing Parameter Verifier dari challenge_params
vk_gamma_abc_0 = parse_g1(GAMMA_ABC_G1[0])
vk_gamma_abc_1 = parse_g1(GAMMA_ABC_G1[1])

# Pre-computation: C = (-GAMMA / DELTA) * IC
delta_inv = pow(DELTA, -1, CURVE_ORDER)
c_scalar = (-GAMMA * delta_inv) % CURVE_ORDER

def format_g1(pt):
    return {"x": hex(pt[0].n), "y": hex(pt[1].n)}

def recv_until(s, delim):
    buf = b""
    while delim.encode() not in buf:
        chunk = s.recv(1)
        if not chunk:
            break
        buf += chunk
    return buf.decode()

def solve():
    print("[*] Menghubungkan ke server challs.squ1rrel.dev:5004...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("challs.squ1rrel.dev", 5004))
    
    for i in range(32):
        # Membaca output server sampai ada prompt "json> "
        round_text = recv_until(s, "json> ")
        print(round_text, end="")
        
        # Ekstrak nilai public out
        out_val = None
        for line in round_text.split('\n'):
            if "public out =" in line:
                out_val = int(line.split("=")[1].strip(), 16)
        
        if out_val is None:
            print("[-] Gagal mengekstrak public out")
            break
            
        # Kalkulasi nilai IC = gamma_abc[0] + (out_val * gamma_abc[1])
        term = multiply(vk_gamma_abc_1, out_val % CURVE_ORDER)
        ic = g1_add(vk_gamma_abc_0, term)
        
        # Kalkulasi nilai tempaan C
        C = multiply(ic, c_scalar)
        
        proof = {
            "proof": {
                "A": ALPHA_G1,
                "B": BETA_G2,
                "C": format_g1(C)
            }
        }
        
        # Kirim payload
        payload = json.dumps(proof)
        s.sendall((payload + "\n").encode())
        print(f"[+] Payload pemalsuan untuk Ronde {i+1} terkirim!")
        
# Menangkap output flag setelah 32 ronde berhasil
    print("\n[*] Menunggu flag dari server... (Server sedang menghitung, sabar ya!)")
    
    # NAIKKAN TIMEOUT JADI 15 DETIK
    s.settimeout(15.0) 
    try:
        while True:
            data = s.recv(4096)
            if not data:
                break
            print(data.decode(), end="")
            
    except socket.timeout:
        print("\n[-] Yah timeout lagi. Servernya lelet banget merespons.")
    except Exception as e:
        print(f"\n[-] Terjadi error: {e}")
        
    print("\n[*] Selesai!")
    s.close()

if __name__ == "__main__":
    solve()

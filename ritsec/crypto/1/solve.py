import math
import ast
from collections import Counter
import string

def solve():
    print("[*] Membaca logbook.txt...")
    try:
        with open("logbook.txt", "r") as f:
            lines = f.readlines()
        tdat = ast.literal_eval(lines[0].replace("Log: ", "").strip())
        ctext = bytes.fromhex(lines[1].replace("Ciphertext: ", "").strip())
    except:
        return

    # 1. Recovery Modulus P 
    V = [tdat[i+1] - tdat[i] for i in range(len(tdat)-1)]
    X = [abs(V[i+1]*V[i-1] - V[i]**2) for i in range(1, len(V)-1)]
    P = 0
    for i in range(len(X)-1):
        if X[i] != 0 and X[i+1] != 0:
            g = math.gcd(X[i], X[i+1])
            if g > 10**50:
                P = math.gcd(P, g) if P != 0 else g
    for i in range(2, 10000):
        while P > 0 and P % i == 0:
            P //= i

    # 2. Recovery 5 State (a,b) Asli
    extracted_pairs = []
    for i in range(len(tdat)-2):
        dy1 = (tdat[i+1] - tdat[i]) % P
        dy2 = (tdat[i+2] - tdat[i+1]) % P
        if dy1 == 0: continue
        a = (dy2 * pow(dy1, -1, P)) % P
        b = (tdat[i+1] - a * tdat[i]) % P
        if (a * tdat[i+1] + b) % P == tdat[i+2]:
            extracted_pairs.append((a, b))
            
    pair_counts = Counter(extracted_pairs)
    heads = [pair for pair, count in pair_counts.items() if count >= 3]

    # 3. REKONSTRUKSI MATRIKS TRANSISI (Machine Learning dari 850 log)
    print("[*] Mempelajari kebiasaan Kapten Mark dari 850 log perjalanan...")
    seq = []
    for i in range(len(tdat)-1):
        for j, (a, b) in enumerate(heads):
            if tdat[i+1] == (a * tdat[i] + b) % P:
                seq.append(j)
                break
    
    # Menghitung probabilitas pergerakan antar state (-log(P) untuk Viterbi scoring)
    score_matrix = [[float('inf')] * len(heads) for _ in range(len(heads))]
    for i in range(len(heads)):
        transitions = [seq[k+1] for k in range(len(seq)-1) if seq[k] == i]
        total = len(transitions)
        if total > 0:
            counts = Counter(transitions)
            for j, count in counts.items():
                score_matrix[i][j] = -math.log(count / total)

    # 4. VITERBI DECODING (Mencari rute probabilitas tertinggi)
    print("[*] Memulai Viterbi Decoding untuk membersihkan noise...")
    last_state = seq[-1]
    paths = [(tdat[-1], b"", last_state, 0.0)]
    beam_width = 100
    
    # Karakter flag normal umumnya alphanumeric dan underscore
    normal_chars = set(string.ascii_letters + string.digits + "_{}")

    for idx, c in enumerate(ctext):
        next_paths = []
        for sval, flag_prefix, curr_idx, score in paths:
            for nxt_idx, head in enumerate(heads):
                trans_score = score_matrix[curr_idx][nxt_idx]
                if trans_score == float('inf'):
                    continue # Abaikan jika transisi ini terbukti mustahil dari data 850 log
                    
                a, b = head
                next_sval = (a * sval + b) % P
                k = next_sval & 0xFF
                pt = c ^ k
                
                if 32 <= pt <= 126:
                    # Tambah penalti jika karakter aneh (seperti % atau ^) agar fokus ke kata bahasa Inggris
                    char_penalty = 0.0 if chr(pt) in normal_chars else 3.0
                    
                    # Guardrail: Karakter format awal dan akhir
                    if idx == 0 and chr(pt) != 'R': continue
                    if idx == 1 and chr(pt) != 'S': continue
                    if idx == 2 and chr(pt) != '{': continue
                    if idx == len(ctext)-1 and chr(pt) != '}': continue
                    
                    new_score = score + trans_score + char_penalty
                    next_paths.append((next_sval, flag_prefix + bytes([pt]), nxt_idx, new_score))
        
        # Sortir berdasarkan SCORE terendah (Probabilitas log-likelihood terbaik)
        next_paths.sort(key=lambda x: x[3])
        paths = next_paths[:beam_width]

    print("\n[✔] BINGO! Harta Karun Utama Berhasil Dibuka:")
    for _, flag, _, score in paths[:1]:
        print(f"--> {flag.decode(errors='ignore')}")

if __name__ == "__main__":
    solve()

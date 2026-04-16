import base64
import string

class _PRNG:
    def __init__(s, x): s._ = x & 0xFFFFFFFF
    def __call__(s):
        s._ ^= (s._ << 13) & 0xFFFFFFFF
        s._ ^= (s._ >> 17)
        s._ ^= (s._ << 5) & 0xFFFFFFFF
        return s._ & 0xFFFFFFFF

def _F(r, k, st):
    z = (r ^ (k & 0xFF))
    z = (z * 173 + 41) & 0xFF
    q = st & 7
    return ((z << q) | (z >> (8 - q))) & 0xFF

def _f_forward(L, R, s, k_list):
    for k in k_list:
        L, R = R, L ^ _F(R, k, s)
        s = (s + k + R) & 0xFFFFFFFF
    return L, R, s

def solve():
    ef = "LE5tUFtNQk46PVtKMjNhZV5VYVxSZW0mSGUkVy45JS0="
    enc_bytes = list(base64.b64decode(ef))
    n = len(enc_bytes)
    seed = 46310
    
    print(f"[*] Menyiapkan state dengan Seed {seed}...")
    prng = _PRNG(seed)
    s_start = prng()
    
    k_seq = []
    for _ in range(n // 2):
        k_seq.append([prng() for _ in range(6)])
        
    p_seq = [prng() % n for _ in range(n)]
    
    idx = list(range(n))
    for i in range(n):
        j = p_seq[i]
        idx[i], idx[j] = idx[j], idx[i]
        
    unperm_enc = [0] * n
    for i, p in enumerate(idx):
        unperm_enc[i] = enc_bytes[p]
        
    cand_unperm = []
    for c in unperm_enc:
        cands = [ (c - 32) + 95 * m for m in range(3) if 0 <= (c - 32) + 95 * m <= 255 ]
        cand_unperm.append(cands)

    P_known = "LNC26{"
    s_curr = s_start
    print(f"[*] Memaksa state 6 byte pertama agar sesuai awalan: {P_known}")
    for i in range(3):
        L = ord(P_known[2*i])
        R = ord(P_known[2*i+1])
        _, _, s_curr = _f_forward(L, R, s_curr, k_seq[i])
        
    print("[*] Melakukan Backtracking (HANYA Alfanumerik & Underscore)...")

    # KUNCI UTAMA: Kita batasi tebakan karakter hanya pada huruf, angka, '_', dan '}'
    valid_charset = set(string.ascii_letters + string.digits + "_{}")
    valid_chars = [ord(c) for c in valid_charset]

    def dfs(pair_idx, current_s, current_flag):
        if pair_idx == n // 2:
            if current_flag.rstrip('\x00').endswith('}'):
                return current_flag
            return None
            
        cL_cands = cand_unperm[2*pair_idx]
        cR_cands = cand_unperm[2*pair_idx+1]
        
        # Izinkan byte \x00 (0) jika ini adalah blok terakhir (untuk padding)
        chars_to_try = valid_chars.copy()
        if pair_idx == (n//2 - 1):
            chars_to_try.append(0)
            
        for L_guess in chars_to_try:
            for R_guess in chars_to_try:
                L_out, R_out, s_next = _f_forward(L_guess, R_guess, current_s, k_seq[pair_idx])
                if L_out in cL_cands and R_out in cR_cands:
                    res = dfs(pair_idx + 1, s_next, current_flag + chr(L_guess) + chr(R_guess))
                    if res: 
                        return res
        return None

    flag = dfs(3, s_curr, P_known)
    if flag:
        print(f"\n[🚀] FLAG ASLI DITEMUKAN: {flag.rstrip(chr(0))}")
    else:
        print("[-] Gagal mengekstrak flag.")

if __name__ == "__main__":
    solve()

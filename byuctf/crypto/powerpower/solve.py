#!/usr/bin/env python3
import socket
import re

def sieve(limit):
    s = [True] * (limit + 1)
    p = 2
    while p * p <= limit:
        if s[p]:
            for i in range(p * p, limit + 1, p):
                s[i] = False
        p += 1
    return [p for p in range(2, limit + 1) if s[p]]

# Pre-compute prime cache for blazing fast factorization
primes_cache = sieve(65537)

def fast_phi(x):
    res = x
    for p in primes_cache:
        if p * p > x:
            break
        if x % p == 0:
            res = res // p * (p - 1)
            while x % p == 0:
                x //= p
    if x > 1:
        res = res // x * (x - 1)
    return res

def get_exact(exps, limit):
    """Mengevaluasi nilai eksak eksponen, return None jika melebihi limit."""
    if len(exps) == 0: return 1
    if len(exps) == 1: return exps[0] if exps[0] <= limit else None
    
    val = exps[-1]
    for i in range(len(exps)-2, -1, -1):
        base = exps[i]
        if val > 10000: return None # Menghindari evaluasi lambat
        try:
            val = base ** val
            if val > limit:
                return None
        except:
            return None
    return val

def get_tower_mod(exps_list, m):
    """Rekursi Generalized Euler's Totient Theorem"""
    if m == 1: return 0
    if len(exps_list) == 0: return 1
    if len(exps_list) == 1: return exps_list[0] % m
    
    exact = get_exact(exps_list[1:], m)
    if exact is not None:
        return pow(exps_list[0], exact, m)
        
    phi_m = fast_phi(m)
    exp_mod = get_tower_mod(exps_list[1:], phi_m)
    return pow(exps_list[0], exp_mod + phi_m, m)

def solve():
    print("[*] Connecting to chals.cyberjousting.com:1359...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('chals.cyberjousting.com', 1359))
    
    # 1. Parsing intercept
    data = b""
    while b"What is m? " not in data:
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk
        
    text = data.decode()
    
    n = int(re.search(r"n = (\d+)", text).group(1))
    c = int(re.search(r"c = (\d+)", text).group(1))
    e_str = re.search(r"e = ([0-9\^]+)", text).group(1)
    exps = [int(x) for x in e_str.split('^')]
    
    print("[*] Intercepted n, c, e. Starting rapid factorization...")
    
    # 2. Factorize n to find phi(n)
    temp_n = n
    phi_n = 1
    for p in primes_cache:
        if p * p > temp_n: break
        if temp_n % p == 0:
            phi_n *= (p - 1)
            temp_n //= p
            while temp_n % p == 0:
                phi_n *= p
                temp_n //= p
    if temp_n > 1:
        phi_n *= (temp_n - 1)
        
    print("[*] n factored successfully. Calculating power tower modulo phi_n...")
    
    # 3. Compute Power Tower modulo phi_n
    E_mod = get_tower_mod(exps, phi_n)
    
    # 4. Modulo Inverse & RSA Decrypt
    d = pow(E_mod, -1, phi_n)
    m = pow(c, d, n)
    
    print(f"[*] Decrypted m: {m}")
    print("[*] Transmitting payload to server...")
    
    # 5. Send Payload & Capture Flag
    s.sendall(f"{m}\n".encode())
    
    s.settimeout(2)
    resp = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            resp += chunk
    except socket.timeout:
        pass
        
    resp_str = resp.decode()
    
    flag_match = re.search(r"(byuctf\{.*?\})", resp_str)
    if flag_match:
        print(f"\n<FLAG>{flag_match.group(1)}</FLAG>")
    else:
        print(f"\n[-] Payload sent, raw server response:\n{resp_str}")

if __name__ == '__main__':
    solve()

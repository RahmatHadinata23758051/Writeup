import socket
import re
import random

# ==========================================
# 1. Standalone Math & CRT Functions
# ==========================================
def ext_euclid(a, b):
    if b == 0: return 1, 0, a
    x, y, g = ext_euclid(b, a % b)
    return y, x - y * (a // b), g

def mod_inv_crt(a, m):
    x, y, g = ext_euclid(a, m)
    if g != 1: raise Exception('Modular inverse does not exist')
    return x % m

def crt(moduli, remainders):
    total = 0
    prod = 1
    for n in moduli: prod *= n
    for n, a in zip(moduli, remainders):
        p = prod // n
        total += a * mod_inv_crt(p, n) * p
    return total % prod, prod

def factorint(n):
    factors = {}
    d = 2
    while d * d <= n:
        while (n % d) == 0:
            factors[d] = factors.get(d, 0) + 1
            n //= d
        d += 1
    if n > 1:
        factors[n] = 1
    return factors

# ==========================================
# 2. Local Elliptic Curve Operations
# ==========================================
P_mod = 10007
A = 2

def mod_inv_ecc(x, p):
    return pow(x % p, -1, p)

def point_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2 and (y1 + y2) % P_mod == 0:
        return None
    if x1 == x2 and y1 == y2:
        s = (3 * x1 * x1 + A) * mod_inv_ecc(2 * y1, P_mod)
    else:
        s = (y2 - y1) * mod_inv_ecc(x2 - x1, P_mod)
    s %= P_mod
    x3 = (s * s - x1 - x2) % P_mod
    y3 = (s * (x1 - x3) - y1) % P_mod
    return (x3, y3)

def get_order_and_dl(P_point, Q_point):
    current = P_point
    k = 1
    dl = None
    while current is not None:
        if current == Q_point and dl is None:
            dl = k
        try:
            current = point_add(current, P_point)
        except ValueError:
            current = None # Division by zero indicates point order is hit
        k += 1
        if k > 20000:
            return None, None
    order = k
    if Q_point is None:
        dl = order
    return dl, order

# ==========================================
# 3. CRT Collector & Network Logic
# ==========================================
prime_powers = {}

def add_congruence(r, m):
    factors = factorint(m)
    for p, e in factors.items():
        pe = p**e
        r_pe = r % pe
        if p in prime_powers:
            old_r, old_pe = prime_powers[p]
            if pe > old_pe:
                if r_pe % old_pe == old_r:
                    prime_powers[p] = (r_pe, pe)
        else:
            prime_powers[p] = (r_pe, pe)

def get_d():
    moduli = []
    remainders = []
    for p, (r, pe) in prime_powers.items():
        moduli.append(pe)
        remainders.append(r)
    if not moduli: return 0, 0
    return crt(moduli, remainders)

def solve():
    print("[*] Connecting to tjc.tf:31313...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("tjc.tf", 31313))
    f = sock.makefile('rwb', buffering=0)

    def read_until(prompt):
        data = b""
        while not data.endswith(prompt):
            char = f.read(1)
            if not char: break
            data += char
        return data

    print("[+] Connected! Starting Invalid Curve Attack...")
    attempts = 0

    while True:
        attempts += 1
        read_until(b"x = ")
        
        x = random.randint(1, P_mod - 1)
        y = random.randint(1, P_mod - 1)
        
        f.write(f"{x}\n".encode())
        read_until(b"y = ")
        f.write(f"{y}\n".encode())
        
        resp = read_until(b"\n").strip().decode()
        
        Q_point = None
        if "Q = inf" in resp:
            Q_point = None
        else:
            match = re.search(r"Q = (\d+) (\d+)", resp)
            if match:
                Q_point = (int(match.group(1)), int(match.group(2)))
            else:
                continue
                
        dl, order = get_order_and_dl((x, y), Q_point)
        
        if dl is not None:
            add_congruence(dl, order)
            d_val, m_val = get_d()
            bits = m_val.bit_length()
            
            print(f"[Attempt {attempts}] Sent P=({x}, {y}) | Modulus Bits: {bits}")
            
            # 300 bits is generally enough to reconstruct a standard string flag
            if bits > 300: 
                try:
                    flag_bytes = d_val.to_bytes((d_val.bit_length() + 7) // 8, 'big')
                    if b'tjc' in flag_bytes or b'}' in flag_bytes:
                        print("\n" + "="*50)
                        print("[!!!] FLAG FOUND:")
                        print(flag_bytes.decode(errors='ignore'))
                        print("="*50 + "\n")
                        break
                except Exception:
                    pass
        else:
            print(f"[Attempt {attempts}] Failed to calculate local order.")

    sock.close()

if __name__ == "__main__":
    solve()

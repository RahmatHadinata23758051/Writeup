from pwn import *

def get_list(io):
    io.sendlineafter(b">>", b"list")
    io.recvuntil(b"Index | Site")
    io.recvline()
    io.recvline()
    entries = []
    while True:
        line = io.recvline().decode().strip()
        if not line or line.startswith("==="): break
        parts = line.split("|")
        if len(parts) >= 3:
            entries.append((parts[1].strip(), parts[2].strip()))
    return entries

def decrypt_block_exact(block_str, K):
    try:
        v = [int(x, 16) for x in block_str.split('.')]
        if len(v) != 4: return ""
        roots = []
        for t in range(0, 256):
            val = t**4 - v[0]*(t**3) + v[1]*(t**2) - v[2]*t + v[3]
            if val == 0:
                mult = 1
                if 4*t**3 - 3*v[0]*t**2 + 2*v[1]*t - v[2] == 0:
                    mult += 1
                    if 12*t**2 - 6*v[0]*t + 2*v[1] == 0:
                        mult += 1
                        if 24*t - 6*v[0] == 0: mult += 1
                roots.extend([t] * mult)
        chars = [chr(r ^ K) for r in roots if (r ^ K) != 0]
        chars.sort()
        return "".join(chars)
    except Exception as e: 
        return f"?({e})"

def main():
    context.log_level = 'error'
    io = remote('chals2.apoorvctf.xyz', 13420)
    io.sendlineafter(b">>", b"add")
    io.sendlineafter(b"site>", b"key_stealer")
    io.sendlineafter(b"password>", b"AAAA")
    entries = get_list(io)

    K = None
    for site, enc in entries:
        if "key_stealer" in site:
            v1 = int(enc.split(';')[0].split('.')[0], 16)
            K = (v1 // 4) ^ 65
            break

    print(f"[*] Kunci XOR: {K}")
    print("[*] Raw Data Vault:")
    for site, enc in entries:
        if "key_stealer" in site: continue
        blocks = [decrypt_block_exact(b, K) for b in enc.split(';') if b]
        raw_flag = "|".join(blocks)
        print(f"{site}: {raw_flag}")
    io.close()

if __name__ == '__main__':
    main()

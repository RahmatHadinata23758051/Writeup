#!/usr/bin/env python3
import re
import random
from collections import defaultdict

CIPHERTEXT = (
    "095 181 145 039 245 091 212 232 123 220 167 069 091 208 245 164 245 145 123 094, "
    "062 150 094 172 083 135 096 153 002 208 096 172. "
    "201 005 019 {131 091 090 053 095 218 238 211 091 004 201 182 135 245 167 074 090 145 096 238}"
)

KNOWN = "maytheforcebewithyouyoungpadawan"


def parse_nums(s: str):
    return list(map(int, re.findall(r"\d+", s)))


def printable(bs):
    return "".join(chr(x) if 32 <= x < 127 else "." for x in bs)


def check_period(arr, max_p=32):
    out = []
    for p in range(1, max_p + 1):
        if all(arr[i] == arr[i % p] for i in range(len(arr))):
            out.append(p)
    return out


def brute_common_rng(target, limit=500000):
    # target: expected byte stream
    MOD31 = 1 << 31

    def gen_glibc(seed, n):
        s = seed
        o = []
        for _ in range(n):
            s = (1103515245 * s + 12345) % MOD31
            o.append(((s >> 16) & 0x7FFF) % 256)
        return o

    def gen_msvc(seed, n):
        s = seed
        o = []
        for _ in range(n):
            s = (214013 * s + 2531011) % MOD31
            o.append(((s >> 16) & 0x7FFF) % 256)
        return o

    class JavaRandom:
        def __init__(self, seed):
            self.seed = (seed ^ 0x5DEECE66D) & ((1 << 48) - 1)

        def nxt(self, bits):
            self.seed = (self.seed * 25214903917 + 11) & ((1 << 48) - 1)
            return self.seed >> (48 - bits)

        def next_byte(self):
            return self.nxt(8)

    def gen_java(seed, n):
        r = JavaRandom(seed)
        return [r.next_byte() for _ in range(n)]

    def gen_py(seed, n):
        r = random.Random(seed)
        return [r.randrange(256) for _ in range(n)]

    gens = {
        "glibc": gen_glibc,
        "msvc": gen_msvc,
        "java": gen_java,
        "python": gen_py,
    }

    hits = {}
    for name, g in gens.items():
        hit = None
        for seed in range(limit):
            if g(seed, 8) != target[:8]:
                continue
            if g(seed, len(target)) == target:
                hit = seed
                break
        hits[name] = hit
    return hits


def main():
    nums = parse_nums(CIPHERTEXT)
    known_ct = nums[: len(KNOWN)]
    tail = nums[len(KNOWN) :]

    print("[+] total nums:", len(nums))
    print("[+] known segment:", len(known_ct), "tail:", len(tail))

    add_stream = [(c - ord(p)) & 0xFF for c, p in zip(known_ct, KNOWN)]
    xor_stream = [c ^ ord(p) for c, p in zip(known_ct, KNOWN)]
    sub_stream = [(ord(p) - c) & 0xFF for c, p in zip(known_ct, KNOWN)]

    print("[+] add periods:", check_period(add_stream, 32))
    print("[+] xor periods:", check_period(xor_stream, 32))

    print("[+] rng brute (seed < 500k)")
    for mode, stream in [("xor", xor_stream), ("add", add_stream), ("sub", sub_stream)]:
        hits = brute_common_rng(stream, limit=500000)
        print("  -", mode, hits)

    # quick key-reuse attempt with known plaintext prefix
    c2 = nums[32:55]
    m1 = KNOWN[:23]
    m1b = [ord(x) for x in m1]

    kx = [a ^ b for a, b in zip(known_ct[:23], m1b)]
    px = [a ^ b for a, b in zip(c2, kx)]
    print("[+] xor key-reuse candidate:", printable(px))

    ka = [(a - b) & 0xFF for a, b in zip(known_ct[:23], m1b)]
    pa = [(a - ka[i]) & 0xFF for i, a in enumerate(c2)]
    print("[+] add key-reuse candidate:", printable(pa))

    print("\n[-] Flag belum terderivasi secara valid dari dataset ini saja.")
    print("[-] Butuh petunjuk tambahan (umumnya source/chall.py) untuk reverse rule enkripsi custom.")


if __name__ == "__main__":
    main()

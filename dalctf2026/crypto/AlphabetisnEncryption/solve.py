#!/usr/bin/env python3
import heapq

ALPHABET = "alphabet.txt"
OUTPUT = "output.txt"

def load_alphabet(path):
    pairs = []
    with open(path, "r") as f:
        for line in f:
            if line.strip():
                ch, freq = line.split()
                pairs.append((ch, float(freq)))
    return pairs

def build_huffman(pairs):
    heap = []

    # reverse tie-breaker penting untuk chall ini
    for i, (ch, freq) in enumerate(pairs):
        heapq.heappush(heap, (freq, -i, ch))

    counter = len(heap)

    while len(heap) > 1:
        f1, _, left = heapq.heappop(heap)
        f2, _, right = heapq.heappop(heap)

        node = (left, right)
        heapq.heappush(heap, (f1 + f2, -counter, node))
        counter += 1

    codes = {}

    def dfs(node, code=""):
        if isinstance(node, str):
            codes[node] = code
            return

        left, right = node
        dfs(left, code + "0")
        dfs(right, code + "1")

    dfs(heap[0][2])
    return codes

def decode(bits, codes):
    rev = {v: k for k, v in codes.items()}

    cur = ""
    out = ""

    for bit in bits:
        cur += bit
        if cur in rev:
            out += rev[cur]
            cur = ""

    if cur:
        raise ValueError(f"leftover bits: {cur}")

    return out

def fix_flag(s):
    # hasil mentah bisa brace ketuker karena frekuensi { dan } sama
    if s.startswith("dalctf}") and s.endswith("{"):
        s = "dalctf{" + s[len("dalctf}"):-1] + "}"

    return s

def main():
    pairs = load_alphabet(ALPHABET)

    with open(OUTPUT, "r") as f:
        bits = f.read().strip()

    codes = build_huffman(pairs)
    decoded = decode(bits, codes)
    flag = fix_flag(decoded)

    print("[raw] ", decoded)
    print("[flag]", flag)

if __name__ == "__main__":
    main()

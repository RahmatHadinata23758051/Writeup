#!/usr/bin/env python3
import os
import re
import socket
import subprocess
from pathlib import Path

HOST = "34.131.216.230"
PORT = 1337
N = 50_000_000

DENSITY = {c: i for i, c in enumerate(" .:-=+*#%@")}
DIGIT_BITS = {
    "111101111001111": "9",
    "111100111001111": "5",
    "111101111101111": "8",
    "111100111101111": "6",
    "001001001001001": "1",
    "111001001001001": "7",
    "111001111100111": "2",
    "111001111001111": "3",
    "101101111001001": "4",
    "111101101101111": "0",
}

FASTSEQ_SRC = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 7) return 1;
    uint64_t s0 = strtoull(argv[1], 0, 10);
    uint64_t s1 = strtoull(argv[2], 0, 10);
    uint64_t C = strtoull(argv[3], 0, 10);
    uint64_t D = strtoull(argv[4], 0, 10);
    uint64_t E = strtoull(argv[5], 0, 10);
    uint64_t n = strtoull(argv[6], 0, 10);

    if (n == 0) {
        printf("%llu\n", (unsigned long long)s0);
        return 0;
    }
    if (n == 1) {
        printf("%llu\n", (unsigned long long)s1);
        return 0;
    }

    uint64_t a = s0, b = s1, c;
    for (uint64_t i = 2; i <= n; i++) {
        c = ((b * C) ^ (a + D)) % E;
        a = b;
        b = c;
    }
    printf("%llu\n", (unsigned long long)b);
    return 0;
}
'''


def ensure_fastseq() -> Path:
    bin_path = Path(".fastseq_bin")
    if bin_path.exists():
        return bin_path
    src_path = Path(".fastseq_tmp.c")
    src_path.write_text(FASTSEQ_SRC)
    try:
        subprocess.check_call([
            "gcc",
            "-O3",
            "-march=native",
            "-pipe",
            str(src_path),
            "-o",
            str(bin_path),
        ])
    finally:
        if src_path.exists():
            src_path.unlink()
    return bin_path


def decode_value(rows, count):
    out = []
    for j in range(count):
        bits = []
        for row in rows:
            seg = row[j * 5:j * 5 + 3].ljust(3)
            bits.extend("1" if DENSITY.get(ch, 0) >= 6 else "0" for ch in seg)
        key = "".join(bits)
        out.append(DIGIT_BITS[key])
    return int("".join(out))


def solve_once():
    fastseq = ensure_fastseq()

    s = socket.create_connection((HOST, PORT), timeout=2)
    s.settimeout(2)

    data = s.recv(8192).decode("latin1", "ignore")
    m = re.search(r"Calculate: (\d+) \* (\d+)", data)
    if not m:
        raise RuntimeError("Task 1 parse failed")
    ans1 = int(m.group(1)) * int(m.group(2))
    s.sendall(f"{ans1}\n".encode())

    while "Find the value of S_50000000" not in data:
        chunk = s.recv(8192)
        if not chunk:
            break
        data += chunk.decode("latin1", "ignore")

    if "Find the value of S_50000000" not in data:
        raise RuntimeError("Task 2 not reached")

    lines = data.splitlines()

    s0 = int(re.search(r"S_0 = (\d+)", data).group(1))
    s1 = int(re.search(r"S_1 = (\d+)", data).group(1))

    def rows_after(tag):
        i = lines.index(tag)
        return lines[i + 1:i + 6]

    C = decode_value(rows_after("--- VALUE OF C ---"), 4)
    D = decode_value(rows_after("--- VALUE OF D ---"), 4)
    E = decode_value(rows_after("--- VALUE OF E ---"), 6)

    ans2 = subprocess.check_output(
        [f"./{fastseq.name}", str(s0), str(s1), str(C), str(D), str(E), str(N)],
        text=True,
    ).strip()

    s.sendall((ans2 + "\n").encode())

    out = ""
    try:
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            out += chunk.decode("latin1", "ignore")
    except socket.timeout:
        pass
    finally:
        s.close()

    print(out.strip())
    mflag = re.search(r"(IIITL\{[^\n\r}]+\})", out)
    if mflag:
        print(mflag.group(1))


if __name__ == "__main__":
    solve_once()

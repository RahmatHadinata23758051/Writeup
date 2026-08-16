#!/usr/bin/env python3
from pathlib import Path
import subprocess

# Constants copied from .rodata and the state machine at check() / 0x1390.
TARGET = bytes.fromhex(
    "febc76f300fb627b8ba26a809581d33329578c65"
    "d453112a4bbb7312af4a4275a24bd83fc4"
)
ROT = bytes.fromhex(
    "030601030702060704040707070301020304020202050405"
    "03050103050106010304030504"
)
MASK = bytes.fromhex(
    "17ca5e5ad650c42936b19508993dd092fa3051b9f1e80dad"
    "d20b1d6e9732968843a148cdee"
)
ADD = bytes.fromhex(
    "98df2c56cdf04be88e48f14504a2b9de8ccc72015c26f1a4"
    "d7c5c0060c7e9987cc496bff58"
)
PERM = bytes.fromhex(
    "021a141d2305011c040b0f0d190c2118081b162411031e20"
    "1512130e00070a09101f062217"
)

FLAG_LEN = 37
PREFIX = b"0xV01D{"
SUFFIX = b"}"

# Printable charset. The validator has a few byte-level collisions, but this
# range keeps the search grounded to a normal CTF flag.
ALLOWED = (
    b"abcdefghijklmnopqrstuvwxyz"
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b"0123456789"
    b"_{}-!@#$%^&*()+[]=;:,./?"
)


def rol32(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def vm_step(i: int, c: int, eax: int, r10: int):
    """Emulate one comparison step from the validator.

    Return next (eax, r10) if byte c satisfies TARGET[i], otherwise None.
    """
    edi = (ADD[i] + c + (17 * i)) & 0xFFFFFFFF
    edi ^= eax

    eax = rol32(edi, ROT[i])
    eax = (eax * 0x45D9F3B) & 0xFFFFFFFF
    eax = (eax + i + 0x27100001) & 0xFFFFFFFF

    shift = (i & 3) * 8
    ecx = ((eax >> shift) + c) & 0xFFFFFFFF

    # The binary does: xor cl, MASK[i]
    ecx = (ecx & 0xFFFFFF00) | (((ecx & 0xFF) ^ MASK[i]) & 0xFF)

    # Then it xors the current rolling state and checks only cl.
    ecx ^= r10
    ecx &= 0xFFFFFFFF
    if (ecx & 0xFF) != TARGET[i]:
        return None

    # Accepted byte updates the rolling state.
    next_r10 = (c + i + ecx) & 0xFFFFFFFF
    return eax, next_r10


def solve_all():
    known = {i: b for i, b in enumerate(PREFIX)}
    known[FLAG_LEN - 1] = SUFFIX[0]

    start = [None] * FLAG_LEN
    for pos, val in known.items():
        start[pos] = val

    out = []

    def dfs(i: int, eax: int, r10: int, flag):
        if i == FLAG_LEN:
            out.append(bytes(flag))
            return

        pos = PERM[i]
        if flag[pos] is not None:
            candidates = [flag[pos]]
        else:
            candidates = ALLOWED

        for c in candidates:
            nxt = vm_step(i, c, eax, r10)
            if nxt is None:
                continue
            new_flag = flag[:]
            new_flag[pos] = c
            dfs(i + 1, nxt[0], nxt[1], new_flag)

    dfs(0, 0x9E3779B9, 0x42, start)
    return out


def score_candidate(flag: bytes) -> int:
    """Prefer the human-readable sentence-like flag if collisions appear."""
    inside = flag[len(PREFIX):-1]
    words = inside.split(b"_")
    score = 0
    for word in words:
        if word:
            score += 3
        if all(chr(c).isalnum() for c in word):
            score += 5
    score -= sum(c not in b"abcdefghijklmnopqrstuvwxyz0123456789_{}" for c in flag) * 20
    score += inside.count(b"_") * 2
    return score


def main():
    candidates = solve_all()
    if not candidates:
        raise SystemExit("no candidate found")

    candidates.sort(key=score_candidate, reverse=True)
    flag = candidates[0]
    print(flag.decode())

    # Optional proof: run the local binary when present.
    binary = Path(__file__).with_name("chronocore")
    if binary.exists():
        p = subprocess.run([str(binary), flag.decode()], capture_output=True, text=True)
        print(p.stdout.strip())


if __name__ == "__main__":
    main()

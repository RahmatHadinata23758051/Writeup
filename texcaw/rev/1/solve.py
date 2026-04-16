#!/usr/bin/env python3
from string import ascii_letters, digits


ALPHABET = ascii_letters + digits + "_"
ALLOWED = [ord(c) for c in ALPHABET]

# Extracted from the real validator at 0x42fe9c.
TARGETS = [
    0x0112996D9AE479FD,
    0x00EFB70B2A601818,
    0x011C799CC5063AC2,
    0x01100D35EADC1177,
]

# Known fixed characters from the expected flag format.
KNOWN = {
    0: ord("t"),
    1: ord("e"),
    2: ord("x"),
    3: ord("s"),
    4: ord("a"),
    5: ord("w"),
    6: ord("{"),
    31: ord("}"),
}


def solve_class(remainder: int) -> str:
    positions = list(range(remainder, 32, 4))
    coeffs = [131 ** (7 - i) for i in range(8)]
    chars = [KNOWN.get(pos) for pos in positions]
    target = TARGETS[remainder]

    suffix_min = [0] * 9
    suffix_max = [0] * 9
    for i in range(7, -1, -1):
        if chars[i] is None:
            lo, hi = min(ALLOWED), max(ALLOWED)
        else:
            lo = hi = chars[i]
        suffix_min[i] = suffix_min[i + 1] + lo * coeffs[i]
        suffix_max[i] = suffix_max[i + 1] + hi * coeffs[i]

    solution = [None] * 8

    def dfs(index: int, remaining: int) -> bool:
        if index == 8:
            return remaining == 0

        coeff = coeffs[index]
        if chars[index] is not None:
            value = chars[index]
            if remaining < value * coeff:
                return False
            solution[index] = value
            return dfs(index + 1, remaining - value * coeff)

        rem_min = suffix_min[index + 1]
        rem_max = suffix_max[index + 1]
        for value in ALLOWED:
            next_remaining = remaining - value * coeff
            if next_remaining < rem_min or next_remaining > rem_max:
                continue
            solution[index] = value
            if dfs(index + 1, next_remaining):
                return True
        return False

    if not dfs(0, target):
        raise RuntimeError(f"no solution for class {remainder}")
    return "".join(chr(x) for x in solution)


def rebuild_flag() -> str:
    parts = {r: solve_class(r) for r in range(4)}
    out = ["?"] * 32
    for remainder, text in parts.items():
        for i, ch in enumerate(text):
            out[remainder + 4 * i] = ch
    return "".join(out)


def validate(flag: str) -> bool:
    if len(flag) != 32:
        return False
    if not flag.startswith("texsaw{") or not flag.endswith("}"):
        return False
    if any(ch not in ALPHABET + "{}" for ch in flag[7:-1]):
        return False

    for remainder, target in enumerate(TARGETS):
        acc = 0
        for index in range(remainder, 32, 4):
            acc = ord(flag[index]) + acc * 131
        if acc != target:
            return False
    return True


def main() -> None:
    flag = rebuild_flag()
    if not validate(flag):
        raise SystemExit("reconstructed flag failed validation")
    print(flag)


if __name__ == "__main__":
    main()

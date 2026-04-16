#!/usr/bin/env python3
import subprocess

M = 0xFFFB
N = 0xFFEF
USERNAME = "gh0st_player"


def init_tab():
    tab = list(range(256))
    seed = 0xB16B00B5
    j = 0
    for i in range(256):
        seed = (seed * 0x19660D + 0x3C6EF35F) & 0xFFFFFFFF
        j = (j + tab[i] + (seed & 0xFF)) & 0xFF
        tab[i], tab[j] = tab[j], tab[i]
    return tab


def hash_user(name, tab):
    v = [1, 1, 1, 1]
    for idx, ch in enumerate(name.encode()):
        c = tab[ch]
        v[0] = (v[0] * c + 0x1234) % M
        v[1] = (v[1] + tab[c] * 0x5678) % M
        v[2] = (v[2] ^ tab[(c + idx) & 0xFF]) % M
        v[3] = (v[3] + (idx + 1) * c) % M
    return [x or 1 for x in v]


def poly(arr, mul, mod):
    r = 0
    for x in arr:
        r = (x + r * mul) % mod
    return r


def calc_s(arr):
    s = sum(arr) & 0xFFFFFFFF
    pop = 0
    while s:
        pop += s & 1
        s >>= 1
    return ((pop ^ 0x2A) % 15) + 2


def make_license(username):
    tab = init_tab()
    t = hash_user(username, tab)
    s = calc_s(t)
    v14 = poly(t, s, M)
    a = [((x ^ (v14 & 0xFF)) % N) or 1 for x in t]
    v18 = poly(a, s, N)
    x = (v14 * v18) % M
    k0 = (0x1337 * pow(x, -1, M)) % M
    k1 = 0x1337
    k2 = s
    k3 = (k1 ^ k0 ^ k2) & 0xFFFF
    return f"{k0:04x}-{k1:04x}-{k2:04x}-{k3:04x}"


def main():
    key = make_license(USERNAME)
    print(f"[+] username: {USERNAME}")
    print(f"[+] license : {key}")
    p = subprocess.run(
        ["./p0lyn0m"],
        input=f"{USERNAME}\n{key}\n",
        text=True,
        capture_output=True,
        check=False,
    )
    print(p.stdout, end="")


if __name__ == "__main__":
    main()

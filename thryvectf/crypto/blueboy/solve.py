#!/usr/bin/env python3
import hashlib
import itertools
from math import gcd, prod
from sympy import factorint, isprime
from sympy.ntheory.residue_ntheory import nthroot_mod
from sympy.ntheory.modular import crt

TARGET = "6f85e84054f1048e167f4841647c59b99d3417d11688241fb948e59947f85153"

cases = [
    (
        7,
        4819780963000543036847069169504018163360725753067212294153426899476640390955209024935335866342406887027536995393135629450102160752728083473501396274439600219523451584953839417300202801908590853108145368699,
        3148161122467153642017282506362130082652016618066045862855690442486127709316851790793914401041285139439255832685518526573428175334698107175851477115468311191313129359931818492718502789691757560997767819416,
    ),
    (
        11,
        3440345489198209637097580092788626053718110038596935900061155514374022205707412805195877930788051623648223485467084528997423155256155588118086990653398632517412481544700159354399305953418281405769996914573,
        1794017083078016983430609694296269997963015581646640945863130438313211890290455458200699678487689659214074910279283544456672629129767630710026674966450807118225569525638097957772897577918727039052814842066,
    ),
    (
        13,
        3789860517070327221919654724854410659071343415974295546509516408064638017928659442246962299239049574698530405323450118373389675056357006642324939698444801650194393595021635959465395424404743767721416691997,
        3710893385296162570574380568207596559686920293640478267543794558584457188311501799541069824030161471113340436672013786181208928543242639879359531928464160443231713556558512978259831098817794458135980063050,
    ),
]

# Faktor yang sudah diketahui dari analisis awal.
# Kalau punya yafu/sage/ecm, lanjutkan factor rem2b dan rem3 lalu tambahkan ke list ini.
known_factors = {
    1: [
        3,
        674057,
        5989547,
        157648093,
        2524217220977654672761667287750307736891301719617952868519420241936609176229015815852153906481882096442801943182799238550537793138391941906068006257327099023987695195994838320502015039,
    ],
    2: [
        157,
        9397,
        81093810773,
        357288655681,
        15463965008977,
        5204576348967150301470174402413469381923538067069102582635345110625752874356767029377037995853369694851854616601479042143328932688523663931836434408500133585144137,
    ],
    3: [
        131,
        18691,
        1547816219289247354594734831702244195198384418991830393331123730637653513255005549164970322590269625908264787324041786193947152201821837199813658816258795268733408288114186465815647660120025014170357,
    ],
}


def is_eth_residue(c, e, p):
    """
    Untuk prime p:
    c punya e-th root modulo p kalau c^((p-1)/gcd(e,p-1)) == 1.
    """
    c %= p
    if c == 0:
        return True
    g = gcd(e, p - 1)
    return pow(c, (p - 1) // g, p) == 1


def main():
    all_mods = []
    all_roots = []

    for idx, (e, n, c) in enumerate(cases, 1):
        print(f"[*] case_{idx}")

        fs = known_factors[idx]

        if prod(fs) != n:
            print("[!] factor list belum complete untuk case ini")
            print("    product bits:", prod(fs).bit_length())
            print("    n bits      :", n.bit_length())

        for p in fs:
            if not isprime(p):
                print(f"    [!] composite cofactor masih perlu difactor:")
                print(f"        {p}")
                continue

            ok = is_eth_residue(c, e, p)
            tag = "GOOD" if ok else "BAD"
            print(f"    {tag:4} p bits={p.bit_length()} p={p}")

            if not ok:
                continue

            roots = nthroot_mod(c % p, e, p, all_roots=True)
            if not roots:
                print("        [!] residue test lolos tapi nthroot kosong")
                continue

            all_mods.append(p)
            all_roots.append(roots)

    print()
    M = prod(all_mods)
    print("[*] usable modulus bits:", M.bit_length())
    print("[*] root combination count:", prod(len(r) for r in all_roots))

    for combo in itertools.product(*all_roots):
        x, mod = crt(all_mods, combo)
        x = int(x)

        # Jika modulus valid sudah lebih besar dari plaintext,
        # flag akan muncul langsung sebagai bytes.
        b = x.to_bytes((x.bit_length() + 7) // 8, "big")

        candidates = [
            b,
            b.rstrip(b"\x00"),
            b.lstrip(b"\x00"),
        ]

        for cand in candidates:
            if cand.startswith(b"Thryve{") and cand.endswith(b"}"):
                h = hashlib.sha256(cand).hexdigest()
                print("[?] candidate:", cand)
                print("    sha256:", h)
                if h == TARGET:
                    print()
                    print(cand.decode())
                    return

    print()
    print("[!] Belum cukup faktor GOOD untuk recover flag.")
    print("[!] Lanjutkan factor composite cofactor rem2b/rem3, lalu masukkan prime factors-nya ke known_factors.")


if __name__ == "__main__":
    main()

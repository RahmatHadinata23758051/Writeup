#!/usr/bin/env python3
# V01D Handout solver
# Three seals:
#   1) Franklin-Reiter related-message RSA -> recover capsule -> PRIME_P
#   2) truncated LCG -> small-error lattice -> recover final seed
#   3) nonlinear combiner of 3 LFSRs -> correlation + linear solve -> decrypt

import hashlib
import re
from fractions import Fraction

# -----------------------------
# Default constants from transmission.txt
# -----------------------------
DEFAULTS = {
    "n": int("25928782651320620641992939140254039773053786143820023022156108435673795888462270829259940673823214637262717952358987391353085730564901510124603705804524112129476757566788142657088664175065593801641965381026991405255727859541175048223240770122323050535833715088675068682271090820084603319348688347351380861828242704714087132514926072521191737125605753678645790120657253978542547752236110505793854886171416458968419171851938582488979266129737463791105500554112134356498730998376352918821416032348958045483800151660133625684914738099274709079396467282048633239278081191552849291204257984704422013322792106841287335460719"),
    "e": 5,
    "delta": int("6833830782908252247261123253047"),
    "c1": int("2271166609354636919573347128840161371936229585863094230781200269193697434103766416960877947863137367309986938975665479588759510782654663865238207041844510373806887525535495510274789717076202255998760674528063535376982602045898972554740783752572007808625255837024569184071895615210635348690959062860007894570514343164562507439453606004265146656456457932347175386259112190734390287327994321167691079767562237904194404573437094738297816979714864588518384761278586142107820759294318139469385737698093641771095573359179821670180757583384120018468170963726551440086225358842440503171717002348714648811598284419231312422128"),
    "c2": int("21509286942876035740813203357561936979765841272579839022736609779635127483686155752043042270306807257492479689909872247694448834824737706970596168518041304670676582963323105074595769264935471267110127006490053258150836273217655012309996504529536284884763861961983138941430380931035377367474034196336478607617884810191902583757301606279109781032863534766846457607838041432051211158968261992230153124492441511171685297367319014610821293109532651264152683844734149471044318252404555037211418912826801581503805886363290247937041102939213895836430529539518384673470765379110379450273823891472725315186603525620809677838951"),
    "a": int("236546365290959227914433225187023916963"),
    "b": int("167616762206619817706864135870591968753"),
    "leak": [3531552479, 2499828603, 2190393553, 1481676222, 1690883128, 2210042718, 41709825, 3439567070],
    "ct": bytes.fromhex("ef10add81097716c9c856a7903d8025a6182a6d0c5219145a72e81c399fac24e7e14493269e45c59f6e560b0a43ae1f115556cee064a8288857249a9a841c889eff03b03fe949dd3838e7d176997513fd9c367cb38faa6536a1342aabc733b1059bb73979549a7ff16f2f744161df3e26b908ff79fedd422ed39f570f773308bbdf3585bed76016a0a3d1a50cc3579d19a043853f9d479d4325e35e01055a37fdbfe97db364aa91481206470e8e3a14eedce7583ca1eabf40a7af3e45d"),
}

E = 5
TRUNC = 96
LENGTHS = (19, 21, 23)
MERSENNE_FACTORS = {
    19: (524287,),
    21: (7, 127, 337),
    23: (47, 178481),
}
HEADER = (b"[0xV0ID // SECURE TRANSMISSION]\n"
          b"NODE   : V-7 (NULLSTAR)\n"
          b"CLASS  : OMEGA / EYES-ONLY\n"
          b"NOTICE : keystream is single-use, do not reissue seals\n"
          b"PAYLOAD: ")
FOOTER = b"\n[EOT]\n"


def parse_transmission(path="transmission.txt"):
    """Use transmission.txt when present, otherwise use embedded constants."""
    try:
        txt = open(path, "r", encoding="utf-8").read()
    except FileNotFoundError:
        return dict(DEFAULTS)

    def grab_int(name):
        m = re.search(rf"^{name}\s*=\s*([0-9]+)", txt, re.M)
        if not m:
            raise ValueError(f"missing {name}")
        return int(m.group(1))

    leak_m = re.search(r"^leak\s*=\s*\[([^\]]+)\]", txt, re.M)
    ct_m = re.search(r"^ct\s*=\s*([0-9a-fA-F]+)", txt, re.M)
    if not leak_m or not ct_m:
        raise ValueError("missing leak/ct")

    return {
        "n": grab_int("n"),
        "e": grab_int("e"),
        "delta": grab_int("delta"),
        "c1": grab_int("c1"),
        "c2": grab_int("c2"),
        "a": grab_int("a"),
        "b": grab_int("b"),
        "leak": [int(x.strip()) for x in leak_m.group(1).split(",")],
        "ct": bytes.fromhex(ct_m.group(1)),
    }


# -----------------------------
# Seal I: Franklin-Reiter RSA
# -----------------------------
def poly_trim(poly, mod):
    poly = [x % mod for x in poly]
    while len(poly) > 1 and poly[-1] == 0:
        poly.pop()
    return poly


def poly_divmod(a, b, mod):
    a = poly_trim(a[:], mod)
    b = poly_trim(b[:], mod)
    if b == [0]:
        raise ZeroDivisionError
    inv_lc = pow(b[-1], -1, mod)
    q = [0] * max(1, len(a) - len(b) + 1)
    while len(a) >= len(b) and a != [0]:
        d = len(a) - len(b)
        coef = a[-1] * inv_lc % mod
        q[d] = coef
        for i in range(len(b)):
            a[i + d] = (a[i + d] - coef * b[i]) % mod
        a = poly_trim(a, mod)
    return poly_trim(q, mod), a


def poly_gcd(a, b, mod):
    a = poly_trim(a, mod)
    b = poly_trim(b, mod)
    while b != [0]:
        _, r = poly_divmod(a, b, mod)
        a, b = b, r
    inv_lc = pow(a[-1], -1, mod)
    return [(x * inv_lc) % mod for x in a]


def recover_capsule(n, delta, c1, c2):
    # gcd(x^5-c1, (x+delta)^5-c2) over Z_n gives x-m.
    f = [(-c1) % n, 0, 0, 0, 0, 1]
    g = [0] * 6
    # coefficients of (x + delta)^5 - c2, low -> high
    binom = [1, 5, 10, 10, 5, 1]
    for k in range(6):
        g[k] = binom[k] * pow(delta, 5 - k, n)
    g[0] = (g[0] - c2) % n
    g = [x % n for x in g]

    h = poly_gcd(f, g, n)
    if len(h) != 2:
        raise RuntimeError(f"unexpected gcd degree {len(h)-1}")
    m = (-h[0]) % n
    return m.to_bytes((m.bit_length() + 7) // 8, "big")


# -----------------------------
# Seal II: truncated LCG lattice
# -----------------------------
def dot(u, v):
    return sum(a * b for a, b in zip(u, v))


def lll_reduction(rows, delta=Fraction(3, 4)):
    """Small exact LLL implementation. Good enough for the 9-dim embedding here."""
    B = [list(map(int, row)) for row in rows]
    n = len(B)
    m = len(B[0])

    def gs():
        mu = [[Fraction(0) for _ in range(n)] for __ in range(n)]
        bstar = [[Fraction(0) for _ in range(m)] for __ in range(n)]
        norm = [Fraction(0) for _ in range(n)]
        for i in range(n):
            bstar[i] = [Fraction(x) for x in B[i]]
            for j in range(i):
                mu[i][j] = Fraction(dot(B[i], bstar[j]), norm[j]) if norm[j] else Fraction(0)
                if mu[i][j]:
                    bstar[i] = [bstar[i][k] - mu[i][j] * bstar[j][k] for k in range(m)]
            norm[i] = sum(x * x for x in bstar[i])
        return mu, norm

    k = 1
    mu, norm = gs()
    while k < n:
        for j in range(k - 1, -1, -1):
            q = int(round(mu[k][j]))
            if q:
                B[k] = [B[k][i] - q * B[j][i] for i in range(m)]
                mu, norm = gs()
        if norm[k] >= (delta - mu[k][k - 1] * mu[k][k - 1]) * norm[k - 1]:
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            mu, norm = gs()
            k = max(k - 1, 1)
    return B


def recover_lcg_seed(p, A, Bc, leaks):
    base = 1 << TRUNC
    Y = [v * base for v in leaks]

    As, Cs = [], []
    aa, cc = 1, 0
    for _ in leaks:
        As.append(aa % p)
        Cs.append(cc % p)
        cc = (A * cc + Bc) % p
        aa = (A * aa) % p

    # x_i = A_i*(Y0+u0)+C_i = Y_i+u_i mod p
    # A_i*u0 - u_i = Y_i - A_i*Y0 - C_i mod p, all u_i < 2^96.
    K = [(Y[i] - As[i] * Y[0] - Cs[i]) % p for i in range(1, len(leaks))]
    dim = len(K) + 2
    M = base

    rows = []
    rows.append([1] + [As[i] for i in range(1, len(leaks))] + [0])
    for j in range(len(K)):
        row = [0] * dim
        row[1 + j] = p
        rows.append(row)
    rows.append([0] + K + [M])

    red = lll_reduction(rows)
    candidates = [r for r in red if abs(r[-1]) == M]

    for row in candidates:
        # The embedding may return +/- the short error vector.
        for sgn in (1, -1):
            us = [sgn * x for x in row[:-1]]
            if not all(0 <= u < base for u in us):
                continue
            x = (Y[0] + us[0]) % p
            ok = True
            for leak in leaks:
                if (x >> TRUNC) != leak:
                    ok = False
                    break
                x = (A * x + Bc) % p
            if ok:
                return x
        # Sometimes signs are mixed only by presentation; absolute values are safe to test.
        us = [abs(x) for x in row[:-1]]
        if all(0 <= u < base for u in us):
            x = (Y[0] + us[0]) % p
            ok = True
            for leak in leaks:
                if (x >> TRUNC) != leak:
                    ok = False
                    break
                x = (A * x + Bc) % p
            if ok:
                return x
    raise RuntimeError("LCG seed not recovered")


# -----------------------------
# Seal III helpers from voidlock.py
# -----------------------------
def gf2_mulmod(a, b, mod, n):
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a >> n & 1:
            a ^= mod
    return r


def gf2_powmod(base, exp, mod, n):
    r, base = 1, base % (1 << n)
    while exp:
        if exp & 1:
            r = gf2_mulmod(r, base, mod, n)
        base = gf2_mulmod(base, base, mod, n)
        exp >>= 1
    return r


def is_primitive(taps, n):
    if not taps & 1:
        return False
    poly = taps | (1 << n)
    order = (1 << n) - 1
    return gf2_powmod(2, order, poly, n) == 1 and all(
        gf2_powmod(2, order // q, poly, n) != 1 for q in MERSENNE_FACTORS[n]
    )


def derive_taps(seed, n, label):
    xof = hashlib.shake_256(
        b"VOIDLOCK/TAPS/" + label + b"/" + seed.to_bytes(16, "big")
    ).digest(8192)
    for i in range(0, len(xof) - 4, 4):
        cand = (int.from_bytes(xof[i:i + 4], "big") & ((1 << n) - 1)) | 1
        if is_primitive(cand, n):
            return cand
    raise RuntimeError("no primitive polynomial found")


def lfsr_clock_state(state, taps, n):
    out = state & 1
    fb = (state & taps).bit_count() & 1
    state = (state >> 1) | (fb << (n - 1))
    return state, out


def bytes_to_bits_msb(data):
    return [(byte >> j) & 1 for byte in data for j in range(7, -1, -1)]


def best_lfsr_phase_by_correlation(taps, n, known_bits):
    """Find phase whose m-sequence has strongest correlation with known keystream."""
    try:
        import numpy as np
    except ImportError as exc:
        raise SystemExit("Need numpy for the fast LFSR correlation step: pip install numpy") from exc

    period = (1 << n) - 1
    N = len(known_bits)

    # Generate one full period plus N-1 bits so every circular window is linear.
    seq = np.empty(period + N - 1, dtype=np.float64)
    state = 1
    for i in range(period + N - 1):
        state, out = lfsr_clock_state(state, taps, n)
        seq[i] = 1.0 if out == 0 else -1.0

    pattern = np.array([1.0 if b == 0 else -1.0 for b in known_bits[::-1]], dtype=np.float64)

    conv_len = len(seq) + N - 1
    fft_len = 1 << (conv_len - 1).bit_length()
    corr = np.fft.irfft(np.fft.rfft(seq, fft_len) * np.fft.rfft(pattern, fft_len), fft_len)
    scores = np.rint(corr[N - 1:N - 1 + period]).astype(np.int32)

    phase = int(scores.argmax())
    score = int(scores[phase])
    matches = (score + N) // 2
    return phase, matches


def state_at_phase(taps, n, phase):
    state = 1
    for _ in range(phase):
        state, _ = lfsr_clock_state(state, taps, n)
    return state


def gen_bits_from_state(taps, n, state, nbits):
    out = []
    for _ in range(nbits):
        state, bit = lfsr_clock_state(state, taps, n)
        out.append(bit)
    return out


def lfsr_output_masks(taps, n, nbits):
    masks = [1 << i for i in range(n)]
    outs = []
    for _ in range(nbits):
        outs.append(masks[0])
        fb = 0
        for i in range(n):
            if (taps >> i) & 1:
                fb ^= masks[i]
        masks = masks[1:] + [fb]
    return outs


def gf2_solve_full_rank(equations, n):
    """Solve linear equations over GF(2). equations: (mask, rhs_bit)."""
    pivots = {}
    for mask, bit in equations:
        row = mask | (bit << n)
        while True:
            coeff = row & ((1 << n) - 1)
            if coeff == 0:
                if (row >> n) & 1:
                    raise RuntimeError("inconsistent GF(2) system")
                break
            p = coeff.bit_length() - 1
            if p in pivots:
                row ^= pivots[p]
            else:
                pivots[p] = row
                break

    if len(pivots) != n:
        raise RuntimeError(f"GF(2) rank {len(pivots)} < {n}")

    # Reduced row echelon form.
    for p in list(pivots.keys()):
        for q in list(pivots.keys()):
            if p != q and ((pivots[q] >> p) & 1):
                pivots[q] ^= pivots[p]

    sol = 0
    for p, row in pivots.items():
        coeff = row & ((1 << n) - 1)
        if coeff != (1 << p):
            raise RuntimeError("RREF failed")
        if (row >> n) & 1:
            sol |= 1 << p
    return sol


def recover_lfsr_states(seed, ct):
    taps = [derive_taps(seed, n, label)
            for n, label in zip(LENGTHS, (b"ALPHA", b"BETA", b"GAMMA"))]

    # Known plaintext prefix gives enough keystream for correlation attacks.
    known_ks = bytes(c ^ p for c, p in zip(ct[:len(HEADER)], HEADER))
    known_bits = bytes_to_bits_msb(known_ks)

    alpha_phase, alpha_matches = best_lfsr_phase_by_correlation(taps[0], LENGTHS[0], known_bits)
    gamma_phase, gamma_matches = best_lfsr_phase_by_correlation(taps[2], LENGTHS[2], known_bits)
    alpha = state_at_phase(taps[0], LENGTHS[0], alpha_phase)
    gamma = state_at_phase(taps[2], LENGTHS[2], gamma_phase)

    alpha_bits = gen_bits_from_state(taps[0], LENGTHS[0], alpha, len(known_bits))
    gamma_bits = gen_bits_from_state(taps[2], LENGTHS[2], gamma, len(known_bits))

    beta_masks = lfsr_output_masks(taps[1], LENGTHS[1], len(known_bits))
    equations = []
    for i, (ks, a, c) in enumerate(zip(known_bits, alpha_bits, gamma_bits)):
        # f = (a&b) ^ (b&c) ^ c = b*(a^c) ^ c
        # If a^c == 1, beta output bit is determined linearly.
        if a ^ c:
            equations.append((beta_masks[i], ks ^ c))
    beta = gf2_solve_full_rank(equations, LENGTHS[1])

    return taps, (alpha, beta, gamma), (alpha_matches, gamma_matches, len(known_bits))


def seal_three_keystream(taps, states, nbytes):
    regs = [[taps[i], states[i], LENGTHS[i]] for i in range(3)]
    out = bytearray()
    for _ in range(nbytes):
        byte = 0
        for _ in range(8):
            bits = []
            for r in regs:
                r[1], bit = lfsr_clock_state(r[1], r[0], r[2])
                bits.append(bit)
            x1, x2, x3 = bits
            z = (x1 & x2) ^ (x2 & x3) ^ x3
            byte = (byte << 1) | z
        out.append(byte)
    return bytes(out)


def main():
    data = parse_transmission()

    print("[+] Seal I: Franklin-Reiter RSA")
    capsule = recover_capsule(data["n"], data["delta"], data["c1"], data["c2"])
    if not capsule.startswith(b"0xV0ID//SEAL-I//"):
        raise RuntimeError("bad capsule magic")
    prime_p = int.from_bytes(capsule[-16:], "big")
    print(f"    PRIME_P = {prime_p:#x}")

    print("[+] Seal II: truncated LCG lattice")
    seed = recover_lcg_seed(prime_p, data["a"], data["b"], data["leak"])
    print(f"    seed    = {seed:#x}")

    print("[+] Seal III: LFSR correlation + GF(2) solve")
    taps, states, info = recover_lfsr_states(seed, data["ct"])
    print("    taps    =", ", ".join(hex(x) for x in taps))
    print("    states  =", ", ".join(hex(x) for x in states))
    print(f"    corr    = alpha {info[0]}/{info[2]}, gamma {info[1]}/{info[2]} matches")

    ks = seal_three_keystream(taps, states, len(data["ct"]))
    pt = bytes(c ^ k for c, k in zip(data["ct"], ks))
    if not (pt.startswith(HEADER) and pt.endswith(FOOTER)):
        raise RuntimeError("plaintext structure check failed")

    flag = pt[len(HEADER):-len(FOOTER)].decode()
    print(f"[+] flag = {flag}")


if __name__ == "__main__":
    main()

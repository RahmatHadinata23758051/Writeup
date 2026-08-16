#!/usr/bin/env python3
# V01D Handout 2 solver
# Python 3 + sympy only.

import hashlib
import struct
from sympy.ntheory.residue_ntheory import sqrt_mod, discrete_log

# ===== Constants copied from deadhand2.py =====
P = 3564625681460390929881227635631045656663925422561280528974142079390139643508987899
A = 1290845814987521891796445286282893750773182431944520388169355126745772946407018553
B = 2548046464103175289844662208531713584748179807189901271913966388343193355335560217
GX = 1457404221189369008358872456999869109718060428281406195376049141321523580448797207
GY = 1290242299127928500851605029070910032280495337570522089014647070915672072669629743

SP = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
SA = 0
SGX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
SGY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
SN = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

ORDER_A = b"ORDER-4417//hold position, node V-7 is clean"
ORDER_B = b"ORDER-4418//burn the channel on my mark"
WARRANT = b"node=V-7&role=observer"
UPGRADE = b"&role=architect&auth="

# ===== Public transcript copied from channel.log =====
node_x = 1325638852438642878998123576357249363240549984609651071545386142674754138299496611
node_y = 468608191669712539538432472947627440322009738671977464971193155685145715350284680

auth_x = 29327505898692726559383869320329077247000077447589821210313273388338028090524
auth_y = 84810498302385529371929497852548539925227545436477666544442075624496782126268
r1 = 54228046796625044020338114295179004736221704259521266121491731787620273057582
s1 = 49862048638765292299426182791447849596212404258046678658538384601415317794992
r2 = 5228908101607893758353029166591071169661964310161311863919069729013330565745
s2 = 109149138641376889053124178510072847015226335736902590340677224192887875508987

observer = bytes.fromhex("2db890900d7b55474dc9de0cbae6e8d56fb381c6f6d032689f30738f0f999a12")
secret_len = 33
ct = bytes.fromhex(
    "9275c2420846dcaf8953c0bd9a6b0673ac362d265d1bc6e58b5cb8eeee4950f4"
    "985bb264bf484b336e19bc429f51dcd033b046ee742e74f0a4396631cd0f2f0"
    "dc6f878b0c500284a0864640dc0d61c4d8635096a414f815abfff9959e32b"
    "653aece7e6ad7e20bc24e0ab7aaf2d3bf3ac145d1ed485d6012df49746"
    "5970a0f8755845c995b9e60f2ecde74a0213"
)


def ec_add(p1, p2, a, m):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % m == 0:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] + a) * pow(2 * p1[1], -1, m) % m
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, m) % m
    x = (lam * lam - p1[0] - p2[0]) % m
    y = (lam * (p1[0] - x) - p1[1]) % m
    return x, y


def ec_mul(k, pt, a, m):
    r = None
    while k:
        if k & 1:
            r = ec_add(r, pt, a, m)
        pt = ec_add(pt, pt, a, m)
        k >>= 1
    return r


def digest(msg):
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % SN


def drift(scalar):
    return int.from_bytes(
        hashlib.sha256(b"DEADHAND/DRIFT/" + str(scalar).encode()).digest(), "big"
    ) % SN


def mdpad(n):
    return b"\x80" + b"\x00" * ((55 - n) % 64) + (n * 8).to_bytes(8, "big")


def keystream(key, n):
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(key + i.to_bytes(8, "big")).digest()
        i += 1
    return out[:n]


def recover_node_scalar():
    # The curve is singular because 4*A^3 + 27*B^2 == 0 mod P.
    assert (4 * pow(A, 3, P) + 27 * pow(B, 2, P)) % P == 0

    # For y^2 = x^3 + A*x + B with a double root alpha:
    # derivative 3*x^2 + A = 0 and alpha^3 + A*alpha + B = 0.
    # Sympy factoring is overkill; brute over the two square roots of -A/3.
    alpha = None
    for cand in sqrt_mod((-A * pow(3, -1, P)) % P, P, all_roots=True):
        if (pow(cand, 3, P) + A * cand + B) % P == 0:
            alpha = cand
            break
    if alpha is None:
        raise RuntimeError("double root not found")

    beta = (-2 * alpha) % P
    tangent = sqrt_mod((alpha - beta) % P, P, all_roots=True)[0]

    def phi(pt):
        x, y = pt
        dx = (x - alpha) % P
        # Nodal singular curve is isomorphic to F_p^*:
        # phi(P) = (y + t*(x-alpha)) / (y - t*(x-alpha)).
        return ((y + tangent * dx) * pow((y - tangent * dx) % P, -1, P)) % P

    g = phi((GX, GY))
    h = phi((node_x, node_y))
    d = int(discrete_log(P, h, g))

    # Sanity check against the original add/mul implementation.
    assert ec_mul(d, (GX, GY), A, P) == (node_x, node_y)
    return d


def recover_auth_private(node_d):
    delta = drift(node_d)
    h1 = digest(ORDER_A)
    h2 = digest(ORDER_B)

    # ECDSA equations:
    #   s1*k       = h1 + x*r1
    #   s2*(k+dlt) = h2 + x*r2
    # Unknowns are k and private key x. Solve the 2x2 linear system mod SN.
    det = (r1 * s2 - s1 * r2) % SN
    x = ((s1 * (h2 - s2 * delta) - s2 * h1) * pow(det, -1, SN)) % SN
    k = ((h1 * (-r2) - (h2 - s2 * delta) * (-r1)) * pow(det, -1, SN)) % SN

    assert ec_mul(x, (SGX, SGY), SA, SP) == (auth_x, auth_y)
    assert ec_mul(k, (SGX, SGY), SA, SP)[0] % SN == r1
    assert ec_mul((k + delta) % SN, (SGX, SGY), SA, SP)[0] % SN == r2
    return x


# Minimal SHA-256 continuation implementation for length extension.
K256 = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def sha256_compress(chunk, h):
    w = list(struct.unpack(">16I", chunk)) + [0] * 48
    for i in range(16, 64):
        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

    a, b, c, d, e, f, g, hh = h
    for i in range(64):
        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ ((~e) & g)
        t1 = (hh + S1 + ch + K256[i] + w[i]) & 0xFFFFFFFF
        S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & 0xFFFFFFFF
        hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xFFFFFFFF, c, b, a, (t1 + t2) & 0xFFFFFFFF

    return [(old + new) & 0xFFFFFFFF for old, new in zip(h, [a, b, c, d, e, f, g, hh])]


def sha256_length_extend(known_digest, append, processed_len):
    h = list(struct.unpack(">8I", known_digest))
    total_len = processed_len + len(append)
    forged_tail = append + b"\x80" + b"\x00" * ((55 - total_len) % 64) + (total_len * 8).to_bytes(8, "big")
    assert len(forged_tail) % 64 == 0

    for i in range(0, len(forged_tail), 64):
        h = sha256_compress(forged_tail[i:i + 64], h)
    return b"".join(v.to_bytes(4, "big") for v in h)


def forge_architect_token(auth_private):
    # observer = SHA256(secret || WARRANT), len(secret)=33.
    # Continue from that internal state over UPGRADE || hex(auth_private).
    original_len = secret_len + len(WARRANT)
    processed_len = original_len + len(mdpad(original_len))
    append = UPGRADE + format(auth_private, "x").encode()
    return sha256_length_extend(observer, append, processed_len)


def main():
    node_d = recover_node_scalar()
    auth_private = recover_auth_private(node_d)
    architect = forge_architect_token(auth_private)

    pt = bytes(a ^ b for a, b in zip(ct, keystream(architect, len(ct))))
    print(pt.decode())


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from pwn import *
from Crypto.Cipher import AES
from hashlib import sha256
from ast import literal_eval
from collections import defaultdict
import sys

HOST = "csc265.instances.ctf.l3ak.team"
PORT = 1337

context.log_level = "info"

# P-256 params
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

G = (
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
)

N = 32
M = 12 * 32
K_HASH = int(round(0.69314718056 * 12))  # 8
SHARES_NEEDED = M // 4                  # 96
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

SSS_P = 0x100000000000000000000000000000033


def inv_mod(x, p=P):
    return pow(x % p, -1, p)


def ec_add(P1, P2):
    if P1 is None:
        return P2
    if P2 is None:
        return P1

    x1, y1 = P1
    x2, y2 = P2

    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    if P1 == P2:
        lam = ((3 * x1 * x1 + A) * inv_mod(2 * y1)) % P
    else:
        lam = ((y2 - y1) * inv_mod(x2 - x1)) % P

    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P

    return (x3, y3)


def ec_neg(P1):
    if P1 is None:
        return None
    x, y = P1
    return (x, (-y) % P)


def ec_sub(P1, P2):
    return ec_add(P1, ec_neg(P2))


def point_to_send(Pt):
    assert Pt is not None
    return f"{Pt[0]} {Pt[1]}".encode()


def sage_point_str(Pt, fmt):
    x, y = Pt

    if fmt == 0:
        return f"({x} : {y} : 1)"

    if fmt == 1:
        return f"({x}, {y})"

    if fmt == 2:
        return f"({x}, {y}, 1)"

    raise ValueError("bad fmt")


def hash_element(m: bytes) -> bytes:
    return sha256(m).digest()[:16]


def xor(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def hash_index(m, ind, mod=M):
    return int.from_bytes(sha256(str(ind).encode() + m).digest(), "big") % mod


def get_indices(m):
    available = list(range(M))
    res = []

    for i in range(K_HASH):
        j = hash_index(m, i, len(available))
        res.append(available.pop(j))

    return res


def decrypt_ot_payload(R, enc_hex, fmt):
    key = hash_element(sage_point_str(R, fmt).encode())
    return xor(key, bytes.fromhex(enc_hex))


def lagrange_zero(shares):
    """
    shares: list of (x, y)
    recover polynomial constant term over SSS_P
    """
    secret = 0

    for i, (xi, yi) in enumerate(shares):
        num = 1
        den = 1

        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue

            num = (num * (-xj)) % SSS_P
            den = (den * (xi - xj)) % SSS_P

        secret = (secret + yi * num * pow(den, -1, SSS_P)) % SSS_P

    return secret.to_bytes(16, "big")


def recv_gbf(io):
    io.recvuntil(b"Printing GBF:\n")

    gbf = []
    for _ in range(M):
        gbf.append(bytes.fromhex(io.recvline().strip().decode()))

    return gbf


def parse_point_line(line):
    parts = line.strip().split()
    assert len(parts) == 2
    return (int(parts[0]), int(parts[1]))


def parse_ot_tuple(line):
    obj = literal_eval(line.decode().strip())
    R = tuple(map(int, obj[0]))
    enc = obj[1]
    return R, enc


def do_ots(io):
    """
    Ambil x0 share untuk 96 index pertama,
    ambil x1 encrypted GBF untuk sisanya.
    """
    share_indices = set(range(SHARES_NEEDED))
    transcripts = []

    io.recvuntil(b"Follow M oblivious transfers:\n")

    for z in range(M):
        C = parse_point_line(io.recvline().decode())

        c_minus_g = ec_sub(C, G)
        if c_minus_g is None:
            raise RuntimeError("C-G is infinity, reconnect")

        want_share = z in share_indices

        if want_share:
            # Ambil branch 0:
            # pk0 = G, pk1 = C - G
            pk0 = G
            pk1 = c_minus_g
        else:
            # Ambil branch 1:
            # pk0 = C - G, pk1 = G
            pk0 = c_minus_g
            pk1 = G

        io.sendlineafter(b"pk0: ", point_to_send(pk0))
        io.sendlineafter(b"pk1: ", point_to_send(pk1))

        R0, e0 = parse_ot_tuple(io.recvline())
        R1, e1 = parse_ot_tuple(io.recvline())

        if want_share:
            transcripts.append(("share", z, R0, e0))
        else:
            transcripts.append(("gbf", z, R1, e1))

        if z % 50 == 0:
            log.info(f"OT progress {z}/{M}")

    return transcripts


def parse_hint(io):
    line = io.recvline_contains(b"Here's a little hint:").decode().strip()

    # Format:
    # Here's a little hint: <hash> <nonce>
    parts = line.split()
    secret_hash = bytes.fromhex(parts[-2])
    nonce = bytes.fromhex(parts[-1])

    return secret_hash, nonce


def build_decrypted_gbf(gbf_printed, transcripts):
    """
    Coba beberapa format string Sage point.
    Format yang benar menghasilkan temp_key valid dan banyak slot
    decrypted sama dengan printed GBF.
    """
    for fmt in range(3):
        shares = []
        x1_ciphertexts = {}

        try:
            for typ, z, R, enc_hex in transcripts:
                payload = decrypt_ot_payload(R, enc_hex, fmt)

                if typ == "share":
                    shares.append((z + 1, int.from_bytes(payload, "big")))
                else:
                    x1_ciphertexts[z] = payload

            temp_key = lagrange_zero(shares)
            cipher = AES.new(temp_key, AES.MODE_ECB)

            dec_known = {}
            matches_printed = 0

            for z, ct in x1_ciphertexts.items():
                val = cipher.decrypt(ct)
                dec_known[z] = val

                if val == gbf_printed[z]:
                    matches_printed += 1

            log.info(f"fmt={fmt}, printed matches={matches_printed}/{len(x1_ciphertexts)}")

            # Kalau format benar, mayoritas slot normal akan match dengan printed GBF.
            # Kalau format salah, match hampir 0.
            if matches_printed > 200:
                log.success(f"selected Sage point string fmt={fmt}")
                return temp_key, dec_known

        except Exception as e:
            log.warning(f"fmt={fmt} failed: {e}")

    raise RuntimeError("cannot recover temp_key / point string format mismatch")


def xor_many(vals):
    out = bytes(16)

    for v in vals:
        out = xor(out, v)

    return out


def recover_secret(gbf_printed, dec_known, nonce, secret_hash):
    """
    Recover SECRET dengan DFS lebih ketat.

    Fix penting:
    - setiap item pasti punya 1 emptySlot special
    - known-special harus dipakai sebagai emptySlot tepat sekali
    - missing-special juga dihitung
    - pada depth i, jumlah special yang sudah dipakai harus == i
    """
    candidates = []

    known_special_set = {
        j for j, v in dec_known.items()
        if v != gbf_printed[j]
    }
    known_normal_set = {
        j for j, v in dec_known.items()
        if v == gbf_printed[j]
    }

    known_special_total = len(known_special_set)
    missing_special_budget = N - known_special_total

    log.info(f"known special slots   = {known_special_total}")
    log.info(f"missing special slots = {missing_special_budget}")

    known_special_list = sorted(known_special_set)
    known_special_id = {j: idx for idx, j in enumerate(known_special_list)}
    all_known_special_mask = (1 << known_special_total) - 1

    pre = {}
    char_order = {}

    for i in range(N):
        opts = []

        for ch in ALPHABET:
            m = str((nonce, i, ord(ch))).encode()
            idxs = get_indices(m)
            h = hash_element(m)

            bitmask = 0
            score = 0

            for j in idxs:
                bitmask |= 1 << j

                if j in dec_known:
                    score += 3
                if j in known_special_set:
                    score += 10
                if j in known_normal_set:
                    score += 2

            pre[(i, ch)] = (idxs, h, bitmask)
            opts.append((score, ch))

        opts.sort(reverse=True)
        char_order[i] = [ch for _, ch in opts]

    sys.setrecursionlimit(10000)

    nodes = 0

    def popcount(x):
        return x.bit_count()

    def slot_value(j, missing_special_values):
        if j in missing_special_values:
            return missing_special_values[j]
        if j in dec_known:
            return dec_known[j]
        return gbf_printed[j]

    def dfs(i, occupied_mask, missing_special_values, used_known_mask, prefix):
        nonlocal nodes
        nodes += 1

        if nodes % 100000 == 0:
            log.info(
                f"dfs nodes={nodes}, i={i}, prefix={prefix}, "
                f"known_used={popcount(used_known_mask)}, "
                f"missing_used={len(missing_special_values)}"
            )

        known_used = popcount(used_known_mask)
        missing_used = len(missing_special_values)

        # Setiap item yang sudah diproses harus menghasilkan tepat 1 special slot.
        if known_used + missing_used != i:
            return False

        if missing_used > missing_special_budget:
            return False

        if known_used > known_special_total:
            return False

        remaining_items = N - i
        remaining_known = known_special_total - known_used
        remaining_missing = missing_special_budget - missing_used

        if remaining_known < 0 or remaining_missing < 0:
            return False

        if remaining_known + remaining_missing != remaining_items:
            return False

        if i == N:
            if used_known_mask != all_known_special_mask:
                return False
            if missing_used != missing_special_budget:
                return False

            sec = prefix.encode()
            if hash_element(sec) == secret_hash:
                candidates.append(prefix)
                return True

            return False

        for ch in char_order[i]:
            idxs, h, bitmask = pre[(i, ch)]

            empty = None
            vals = []
            ok = True

            for j in idxs:
                occupied = ((occupied_mask >> j) & 1) == 1

                if occupied:
                    vals.append(slot_value(j, missing_special_values))
                    continue

                if empty is None:
                    # First free slot pada item ini adalah emptySlot special.
                    empty = j

                    # Known-normal tidak mungkin menjadi emptySlot special.
                    if j in known_normal_set:
                        ok = False
                        break
                else:
                    # Slot free setelah empty akan diisi random normal.
                    # Jadi known-special tidak boleh berada di sini.
                    if j in known_special_set:
                        ok = False
                        break

                    # Kalau slot ini sebelumnya dianggap missing-special,
                    # tapi belum occupied, itu kontradiksi.
                    if j in missing_special_values:
                        ok = False
                        break

                    vals.append(gbf_printed[j])

            if not ok or empty is None:
                continue

            cur = xor_many(vals)
            needed_empty_value = xor(cur, h)

            new_missing = missing_special_values
            new_used_known_mask = used_known_mask

            if empty in known_special_set:
                sid = known_special_id[empty]

                # Known-special tidak boleh dipakai dua kali.
                if (used_known_mask >> sid) & 1:
                    continue

                # Nilai decrypted known-special harus cocok.
                if dec_known[empty] != needed_empty_value:
                    continue

                new_used_known_mask = used_known_mask | (1 << sid)

            elif empty in known_normal_set:
                continue

            else:
                # Empty slot ini special tapi tidak kita ambil via OT.
                if empty in missing_special_values:
                    if missing_special_values[empty] != needed_empty_value:
                        continue
                else:
                    if len(missing_special_values) >= missing_special_budget:
                        continue

                    new_missing = dict(missing_special_values)
                    new_missing[empty] = needed_empty_value

            if dfs(
                i + 1,
                occupied_mask | bitmask,
                new_missing,
                new_used_known_mask,
                prefix + ch,
            ):
                return True

        return False

    dfs(0, 0, {}, 0, "")

    if not candidates:
        raise RuntimeError("secret not recovered")

    return candidates[0]

def solve_once():
    io = remote(HOST, PORT, ssl=True)

    gbf_printed = recv_gbf(io)
    log.success("got printed GBF")

    transcripts = do_ots(io)
    log.success("finished OT")

    secret_hash, nonce = parse_hint(io)

    log.info(f"hint hash = {secret_hash.hex()}")
    log.info(f"nonce     = {nonce.hex()}")

    temp_key, dec_known = build_decrypted_gbf(gbf_printed, transcripts)
    log.success(f"temp key = {temp_key.hex()}")

    secret = recover_secret(gbf_printed, dec_known, nonce, secret_hash)
    log.success(f"SECRET = {secret}")

    io.sendlineafter(b"What's my secret: ", secret.encode())

    print(io.recvall(timeout=5).decode(errors="ignore"))


def main():
    while True:
        try:
            solve_once()
            break
        except KeyboardInterrupt:
            raise
        except Exception as e:
            log.failure(str(e))
            log.info("reconnecting...")


if __name__ == "__main__":
    main()

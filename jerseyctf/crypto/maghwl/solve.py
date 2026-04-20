#!/usr/bin/env python3
import re
import math
import base64
from pathlib import Path
from collections import Counter

CIPHERTEXT = """m_`_gu_e__lb_yt_D__`oIfg}lyag_yh`S_St_.`oajIQna``{a_uIthma__uSuar_o.
Sa'aab_.tnD'SlaaSySturjoom__b_Qy``_l_aDuhnn_eultm_jm_bblrq'eejhmbIv
HHgm_vhleHmweoIueu!jlcIau'_aa_aQ.nhnoaIjrr'H'_yptnHQ__""".replace("\n", "")


def caesar_letters(s, k):
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + k) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + k) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def shift_printable(s, k):
    out = []
    for c in s:
        o = ord(c)
        if 32 <= o <= 126:
            out.append(chr((o - 32 + k) % 95 + 32))
        else:
            out.append(c)
    return "".join(out)


def extract_raw_from_pdf(pdf_qdf_path):
    data = Path(pdf_qdf_path).read_text(errors="ignore")
    hexes = re.findall(r"<([0-9A-Fa-f]+)> Tj", data)
    msg = "".join("".join(chr(int(h[i:i+4], 16)) for i in range(0, len(h), 4)) for h in hexes if len(h) > 4)
    return msg


def transposition_box_round(s, w):
    h = math.ceil(len(s) / w)
    pad = "~"
    s2 = s + pad * (w * h - len(s))
    m = [s2[r * w:(r + 1) * w] for r in range(h)]
    out = "".join(m[r][c] for c in range(w) for r in range(h))
    return out.replace(pad, "")


def transposition_box_unround(s, w):
    h = math.ceil(len(s) / w)
    n = len(s)
    pad = "~"
    s2 = s + pad * (w * h - n)
    # reconstruct columns
    cols = []
    p = 0
    for c in range(w):
        col = [s2[p + r] for r in range(h)]
        p += h
        cols.append(col)
    out = []
    for r in range(h):
        for c in range(w):
            out.append(cols[c][r])
    return "".join(out).replace(pad, "")


def try_custom_base32(ct):
    syms = sorted(set(ct))
    if len(syms) != 32:
        return None
    b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    mapped = "".join(b32[syms.index(ch)] for ch in ct)
    mapped += "=" * ((8 - len(mapped) % 8) % 8)
    try:
        return base64.b32decode(mapped)
    except Exception:
        return None


def main():
    print("[*] Cipher length:", len(CIPHERTEXT))
    print("[*] Unique symbols:", len(set(CIPHERTEXT)), sorted(set(CIPHERTEXT)))
    print("\n[*] Caesar letters (k=23):")
    print(caesar_letters(CIPHERTEXT, 23)[:220])

    print("\n[*] ASCII printable shift (k=-29):")
    print(shift_printable(CIPHERTEXT, -29)[:220])

    if Path("Note_Found.qdf.pdf").exists():
        raw = extract_raw_from_pdf("Note_Found.qdf.pdf")
        print("\n[*] Raw stream extracted length:", len(raw))
        print(raw[:220])

    print("\n[*] Box unround sample (w=23, repeated 23x):")
    s = CIPHERTEXT
    for _ in range(23):
        s = transposition_box_unround(s, 23)
    print(s[:220])

    b = try_custom_base32(CIPHERTEXT)
    if b is not None:
        print("\n[*] Custom base32 candidate bytes len:", len(b))
        print("ASCII preview:", "".join(chr(x) if 32 <= x < 127 else "." for x in b[:220]))

    print("\n[!] Status: automated paths executed, plaintext/flag not recovered yet.")


if __name__ == "__main__":
    main()

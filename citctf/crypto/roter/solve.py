#!/usr/bin/env python3
import string

CT = "KLEGCKRGGONTBNBVPIIZWXQQEZYAXXWQMGIZDNEWWUTOVZRWOMZKGWNKWZBQXOGZSTVCGU"
A = string.ascii_uppercase
A2I = {c: i for i, c in enumerate(A)}

# Enigma rotors (left, middle, right fixed as I-II-III)
R_I = "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
R_II = "AJDKSIRUXBLHWTMCQGZNPYFVOE"
R_III = "BDFHJLCPRTXVZNYEIWGAKMUSQO"
REF_B = "YRUHQSLDPXNGOKMIEBFZCWVJAT"


def build_rotor(wiring: str):
    fwd = [A2I[c] for c in wiring]
    rev = [0] * 26
    for i, v in enumerate(fwd):
        rev[v] = i
    return fwd, rev


LF, LR = build_rotor(R_I)
MF, MR = build_rotor(R_II)
RF, RR = build_rotor(R_III)
REF = [A2I[c] for c in REF_B]


def decrypt_with_notch(right_notch: int, middle_notch: int = A2I["E"]) -> str:
    # Start positions AAA
    pL = pM = pR = 0
    out = []

    for ch in CT:
        x = A2I[ch]

        # stepping (simplified model used by challenge behavior)
        if pM == middle_notch:
            pM = (pM + 1) % 26
            pL = (pL + 1) % 26
        elif pR == right_notch:
            pM = (pM + 1) % 26
        pR = (pR + 1) % 26

        # right -> middle -> left
        x = (RF[(x + pR) % 26] - pR) % 26
        x = (MF[(x + pM) % 26] - pM) % 26
        x = (LF[(x + pL) % 26] - pL) % 26
        x = REF[x]
        # left -> middle -> right
        x = (LR[(x + pL) % 26] - pL) % 26
        x = (MR[(x + pM) % 26] - pM) % 26
        x = (RR[(x + pR) % 26] - pR) % 26

        out.append(A[x])

    return "".join(out)


def score_text(t: str) -> int:
    keys = [
        "WECAN", "ONLY", "SHORT", "DISTANCE", "AHEAD", "PLENTY",
        "THERE", "NEEDS", "DONE", "THE", "ING", "AND"
    ]
    bad = ["QJ", "JQ", "QZ", "ZX", "XQ"]
    s = sum(t.count(k) * 3 for k in keys)
    s -= sum(t.count(b) * 2 for b in bad)
    return s


def to_flag(words):
    return "CIT{" + "_".join(words) + "}"


def main():
    cands = []
    for n in range(26):
        pt = decrypt_with_notch(n)
        cands.append((score_text(pt), n, pt))

    cands.sort(reverse=True)

    print("Top plaintext candidates (by score):")
    for sc, n, pt in cands[:5]:
        print(f"notch={A[n]} score={sc} -> {pt}")

    # Best corrected quote appears at notch T
    pt_t = decrypt_with_notch(A2I["T"])
    print("\nBest corrected decode (notch T):")
    print(pt_t)

    # Main expected-word split
    words_main = [
        "we", "can", "only", "see", "a", "short", "distance", "ahead", "but",
        "we", "can", "see", "plenty", "there", "that", "needs", "to", "be", "done"
    ]
    print("flag_main:", to_flag(words_main))

    # Typo-like decode from historical notch V (for fallback)
    pt_v = decrypt_with_notch(A2I["V"])
    print("\nFallback decode (notch V):")
    print(pt_v)

    fallback_flags = [
        ["we", "can", "only", "see", "a", "short", "dnhtance", "ahead", "but", "we", "can", "see", "pleigy", "there", "that", "needs", "to", "be", "done"],
        ["we", "can", "only", "see", "a", "short", "dnh", "tance", "ahead", "but", "we", "can", "see", "plei", "gy", "there", "that", "needs", "to", "be", "done"],
        ["we", "can", "only", "see", "a", "short", "dnh", "tance", "ahead", "but", "we", "can", "see", "pleigy", "there", "that", "needs", "to", "be", "done"],
    ]

    print("fallback_flag_variants:")
    for wf in fallback_flags:
        print(to_flag(wf))


if __name__ == "__main__":
    main()

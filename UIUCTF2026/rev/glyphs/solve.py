#!/usr/bin/env python3
"""
Solver for glyphs (UIUCTF rev).

The binary checks a lambda-calculus tree generated from the input.  Reversing the
final check gives a 73-block input, where each block is either the last single
character or a 2-character chunk read from the end of the string.  The checker
only constrains 58 of those 73 blocks; the remaining blocks are semantically
filled to restore the author's readable sentence.

Run:
    python3 solve.py
    ./glyphs "$(python3 solve.py)"
"""

# String directly recovered from the checked blocks.  The 'A' positions below
# are unconstrained by the checker; the local binary accepts any printable bytes
# at those positions as long as the checked blocks and length stay unchanged.
template = list(
    "uiuctf{oRig1naLLy_7HiAAW4s_gonna_be_moR3_FoCU53d_0N_the_"
    "GAAAA_p4rt_BU7_AAf3AA_d0WN_7h3_AAmbD4_c4lc_R4AAAA_H0Le_"
    "AA_HAA3_w3AAr3_noW_4AA7_7H47_gAAat}"
)

# Fill unconstrained positions with the obvious intended leetspeak sentence:
# "originally this was gonna be more focused on the games part but I fell down
# the lambda calc rabbit hole so here we are now ain't that great"
patches = {
    21: "s", 22: "_",          # 7His_W4s
    57: "4", 58: "M", 59: "3", 60: "s",  # G4M3s_p4rt
    71: "1", 72: "_", 75: "l", 76: "l",  # BU7_1_f3ll
    87: "l", 88: "4",          # l4mbD4
    101: "b", 102: "b", 103: "1", 104: "7",  # R4bb17
    111: "5", 112: "0",        # 50
    115: "e", 116: "R",        # HeR3
    121: "_", 122: "4",        # w3_4r3
    131: "1", 132: "n",        # 41n7
    141: "R", 142: "3",        # gR3at
}

for idx, ch in patches.items():
    template[idx] = ch

flag = "".join(template)
assert flag.startswith("uiuctf{") and flag.endswith("}")
assert len(flag) == 146

print(flag)


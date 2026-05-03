key = bytes.fromhex("deadbeef42")
packets = [
    "cc53020937", # P2
    "ccb9022011", # P3
    "cc75021617", # P4
    "cccb02392c", # P5
    "ccb102721d", # P6
    "cc61022f72", # P7
    "cc8e023071", # P8
    "cc00021d25", # P9
    "ccc8023071", # P10
    "cc40023232", # P11
    "cc6502732c", # P12
    "cc3b02251d", # P13
    "ccda02732c", # P14
    "cc2a021d36", # P15
    "cc45022a71", # P16
    "cc21021d26", # P17
    "cc45027630", # P18
    "cc2602291d", # P19
    "cc3f023470", # P20
    "cc1e013f"    # P21
]

data = []
for p_hex in packets:
    p = bytes.fromhex(p_hex)
    data.extend(p[3:])

# The user mentioned P2[4]^Key[4]='u', P3[3]^Key[4]='b', P5[3]^Key[4]='{'
# This implies Key[4] (0x42) is a common XOR key.
# We also noticed that XORing with 0x62 (0x42 ^ 0x20) changes case.

flag = ""
for b in data:
    res = b ^ 0x42
    # Heuristic: if it's an uppercase letter that should probably be lowercase, flip it.
    if ord('A') <= res <= ord('Z'):
        # For 'KubSTU', we know the first few should be 'kubsu'
        # 'K' -> 'k' (0x4b ^ 0x20 = 0x6b)
        # 'S' -> 's' (0x53 ^ 0x20 = 0x73)
        # 'T' -> 'u'? (0x54 ^ 0x21 = 0x75) - Wait, this is not a simple case flip.
        pass
    flag += chr(res)

print(flag)

# solve_requiem.py
with open("flag_enc.bin", "rb") as f:
    flag_enc = f.read()
with open("key_r13.bin", "rb") as f:
    key = f.read()

# Percobaan 1: Simple XOR antara data di R15 dan R13
flag1 = "".join(chr(flag_enc[i] ^ key[i]) for i in range(len(flag_enc)))
print(f"XOR Result: {flag1}")

# Percobaan 2: Substraction (Data - Key)
flag2 = "".join(chr((flag_enc[i] - key[i]) % 256) for i in range(len(flag_enc)))
print(f"Sub Result: {flag2}")

# Percobaan 3: Substraction (Key - Data)
flag3 = "".join(chr((key[i] - flag_enc[i]) % 256) for i in range(len(flag_enc)))
print(f"Key-Data Result: {flag3}")

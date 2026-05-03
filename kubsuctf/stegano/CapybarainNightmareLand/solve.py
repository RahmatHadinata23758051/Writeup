key = "N1ghtm4r3_C4py_2026"
encrypted_hex = "0544053b20384f3a03333a6b3d49334b6f71573e482f09370605004e"
encrypted = bytes.fromhex(encrypted_hex)
flag = ''.join(chr(b ^ ord(key[i % len(key)])) for i, b in enumerate(encrypted))
print(flag)

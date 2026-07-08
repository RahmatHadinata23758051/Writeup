desc_hex = "6d14166842b6ecb67622284a65bde8a87e03344564bde3ab7e1e324b648dc4a87e0a2f4976bdffbd7e0233435ea6cbb45c"
ct = bytes.fromhex(desc_hex)
prefix = b"LYKNCTF{"
key = bytes([b ^ p for b, p in zip(ct[:8], prefix)])
flag = bytes([ct[i] ^ key[i % len(key)] for i in range(len(ct))]).decode()
print(flag)

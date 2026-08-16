cipher_hex = "723a147273063915710e01720f711d16721d0116043f"
cipher_bytes = bytes.fromhex(cipher_hex)
key = 0x42

flag = "".join([chr(b ^ key) for b in cipher_bytes])
print(flag)


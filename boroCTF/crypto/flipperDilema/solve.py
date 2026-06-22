cipher = "wzgzVASnS4|eE${J%`>h"
key = 0x15

flag = "".join(chr(ord(c) ^ key) for c in cipher)
print(f"Flag: {flag}")

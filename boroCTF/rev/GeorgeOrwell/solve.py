# Reconstruct the flag from the Chr() values found in the binary strings
chars = [98, 111, 114, 111, 67, 84, 70, 123, 65, 72, 75, 95, 49, 115, 95, 108, 73, 115, 43, 101, 110, 105, 52, 103, 125]
flag = "".join(chr(c) for c in chars)
print(flag)

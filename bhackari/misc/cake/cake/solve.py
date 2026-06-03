
mapping = {
    'a': 0, 'b': 1, 'c': 2, 'd': 3, 'e': 4, 'f': 5, 'g': 6, 'h': 7, 'i': 8, 'j': 9,
    'k': 10, 'l': 11, 'm': 12, 'n': 13, 'o': 14, 'p': 15, 'q': 16, 'r': 17, 's': 18, 't': 19,
    'u': 20, 'v': 21, 'w': 22, 'x': 23, 'y': 24, 'z': 25, 'A': 26, 'B': 27, 'C': 28, 'D': 29,
    'E': 30, 'F': 31, 'G': 32, 'H': 33, 'I': 34, 'J': 35, 'K': 36, 'L': 37, 'M': 38, 'N': 39,
    'O': 40, 'P': 41, 'Q': 42, 'R': 43, 'S': 44, 'T': 45, 'U': 46, 'V': 47, 'W': 48, 'X': 49,
    'Y': 50, 'Z': 51, '0': 52, '1': 53, '2': 54, '3': 55, '4': 56, '5': 57, '6': 58, '7': 59,
    '8': 60, '9': 61, '_': 62
}

uuid = [1925805954, -557366980, -1859783841, -1036135955]
k_vals = [u % 63 for u in uuid]
print(f"k_vals: {k_vals}")

target_enc = []
tmp = 29
target_enc.append(tmp)
tmp -= 22; target_enc.append(tmp)
tmp += 22; target_enc.append(tmp)
tmp += 18; target_enc.append(tmp)
tmp -= 18; target_enc.append(tmp)
tmp -= 16; target_enc.append(tmp)
tmp += 22; target_enc.append(tmp)
tmp += 6;  target_enc.append(tmp)
tmp -= 18; target_enc.append(tmp)
tmp += 3;  target_enc.append(tmp)
tmp += 2;  target_enc.append(tmp)
tmp += 5;  target_enc.append(tmp)
tmp -= 10; target_enc.append(tmp)
tmp -= 19; target_enc.append(tmp)
tmp += 50; target_enc.append(tmp)
tmp -= 9;  target_enc.append(tmp)
tmp -= 25; target_enc.append(tmp)
tmp -= 13; target_enc.append(tmp)
tmp += 21; target_enc.append(tmp)
tmp += 5;  target_enc.append(tmp)

password = ""
for i in range(20):
    k = k_vals[i % 4]
    found = False
    for char, val in mapping.items():
        if (val + k) % 63 == target_enc[i]:
            password += char
            found = True
            break
    if not found:
        password += "?"

print(f"Password: {password}")

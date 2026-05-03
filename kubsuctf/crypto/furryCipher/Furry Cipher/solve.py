import string

alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits
char_map = {ch: i for i, ch in enumerate(alphabet)}
num_map = {i: ch for i, ch in enumerate(alphabet)}

pt = "KubSTU"
ct = "XiEDJ5"

key = [0, 0, 0]

for k in range(256):
    if (char_map['K'] * 13 + k * 7) % 62 == char_map['X']:
        key[0] = k
    if (char_map['u'] * 17 + k * 3 + 11) % 62 == char_map['i']:
        key[1] = k
    if (char_map['b'] * 19 + (k ^ 42) + 23) % 62 == char_map['E']:
        key[2] = k

print("Found key:", key)

def decrypt(ciphertext, key_values):
    result = []
    for i, char in enumerate(ciphertext):
        if char in '()_':
            result.append(char)
        elif char in char_map:
            c_num = char_map[char]
            key_val = key_values[i % 3]
            
            if i % 3 == 0:
                inv13 = pow(13, -1, 62)
                p_num = ((c_num - key_val * 7) * inv13) % 62
            elif i % 3 == 1:
                inv17 = pow(17, -1, 62)
                p_num = ((c_num - key_val * 3 - 11) * inv17) % 62
            else:
                inv19 = pow(19, -1, 62)
                p_num = ((c_num - (key_val ^ 42) - 23) * inv19) % 62
                
            result.append(num_map[p_num])
        else:
            result.append(char)
    return ''.join(result)

ct_full = "XiEDJ5(9tV_qY3_v43_t9B3_o9vo_ESM_YR_YA_t_S5t8v_XYL4jt)"
print("<FLAG>" + decrypt(ct_full, key) + "</FLAG>")

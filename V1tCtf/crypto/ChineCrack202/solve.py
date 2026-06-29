import struct
import zlib

cipher_flag = bytes.fromhex("72901442adade9c53b7cb386eeb8b6765d42dbc58ec6d442e77057b7d5d2724afc2f4e232df02f9ff050")
leak1 = [123, 38, 92, 78, 207, 178, 116, 75, 141, 163]
leak2 = [4226, 36575, 42265, 42988, 32134, 53660, 36202, 48971, 61905, 20150, 45745]
leak3 = [10, 18, 13, 17, 17, 19, 14, 13, 18, 16, 15]
partial_crc = 0x32c29a97

w0_bytes = bytes(a ^ b for a, b in zip(cipher_flag[:4], b"V1T{"))
w0_val = struct.unpack(">I", w0_bytes)[0]

pop_count_table = [bin(i).count('1') for i in range(256)]
def popcount32(w):
    return pop_count_table[w & 0xff] + pop_count_table[(w >> 8) & 0xff] + pop_count_table[(w >> 16) & 0xff] + pop_count_table[(w >> 24) & 0xff]

allowed_chars = set(range(32, 127))

all_candidates = []
for i in range(len(leak2)):
    l2 = leak2[i]
    l3 = leak3[i]
    candidates = []
    
    start_idx = 4 * i
    end_idx = min(4 * i + 4, len(cipher_flag))
    num_bytes = end_idx - start_idx
    c_slice = cipher_flag[start_idx:end_idx]
    
    for Y in range(65536):
        X = l2 ^ ((Y * 0x45d9f3b) & 0xFFFF)
        W = (X << 16) | Y
        if popcount32(W) == l3:
            w_bytes = W.to_bytes(4, 'big')[:num_bytes]
            valid = True
            for b_c, b_w in zip(c_slice, w_bytes):
                if (b_c ^ b_w) not in allowed_chars:
                    valid = False
                    break
            if valid:
                candidates.append(W)
    all_candidates.append(candidates)

paths = [[w0_val]]
for i in range(1, len(leak2)):
    l1 = leak1[i-1]
    candidates_i = all_candidates[i]
    new_paths = []
    for path in paths:
        w_prev = path[-1]
        for W in candidates_i:
            if (((w_prev ^ W) * 0x9e3779b1) & 0xFFFFFFFF) >> 24 == l1:
                new_paths.append(path + [W])
    paths = new_paths

for path in paths:
    keystream = b"".join(w.to_bytes(4, "big") for w in path)[:len(cipher_flag)]
    flag = bytes(a ^ b for a, b in zip(cipher_flag, keystream))
    if zlib.crc32(flag[:16]) == partial_crc:
        try:
            flag_str = flag.decode()
            if flag_str.endswith("}"):
                print(flag_str)
        except Exception:
            pass

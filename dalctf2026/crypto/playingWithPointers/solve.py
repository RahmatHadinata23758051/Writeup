import struct
import math

# Data dari output.txt
outputs = [
    1167097856, 1175651328, 1177960448, 1166821376, 1172078592, 1167663104,
    1181508608, 1179558912, 1158676480, 1178182656, 1159892992, 1175258112,
    1176670208, 1172424704, 1178406912, 1175258112, 1180517376, 1159073792,
    1161629696, 1177092096, 1175258112, 1170735104, 1158676480, 1159073792,
    1178406912, 1161629696, 1159892992, 1179324416, 1160744960, 1182016512
]

flag = ""

for val in outputs:
    # 1. Ubah integer 32-bit ke bytes, lalu unpack sebagai float (IEEE 754)
    # Gunakan 'I' untuk unsigned int dan 'f' untuk float
    packed = struct.pack('<I', val)
    float_val = struct.unpack('<f', packed)[0]
    
    # 2. Karena di chall di-kuadratkan (fflag[i] * fflag[i]), kita ambil akar kuadratnya
    ascii_val = int(round(math.sqrt(float_val)))
    
    # 3. Gabungkan ke flag
    flag += chr(ascii_val)

print(f"[+] Flag berhasil didekripsi!")
print(f"FLAG: {flag}")

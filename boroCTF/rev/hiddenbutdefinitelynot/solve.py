# 1. 16 Karakter pertama diambil dari password yang kita masukkan ke stack frame
password = "Rate5StarsBecauseGreatChallenge"
part1 = password[0:16] # Mengambil 16 karakter pertama dari stack frame [0x1a0 sampai 0x191]

# 2. Sisanya diambil dari 19 byte hardcoded yang barusan kita extract
cipher_hex = [
    0x30, 0x6e, 0x69, 0x60, 0x58, 0x54, 0x73, 0x55, 
    0x36, 0x69, 0x60, 0x32, 0x58, 0x64, 0x4f, 0x66, 
    0x6b, 0x74, 0x7a
]
part2 = "".join([chr(b ^ 7) for b in cipher_hex])

# Gabungkan seluruh potongan flag
print(f"Flag: {part1}{part2}")

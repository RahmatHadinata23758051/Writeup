# Hasil decode Morse awal (dengan spasi)
morse_output = "V3 0 7 8 5 6 3 0 4 9 4 4 7 B 7 3 3 1 6 7 6 E 3 4 6 C 5 U 6 4 3 3 6 3 3 0 6 4 3 3 6 4 5 F 6 C 3 4 7 9 3 3 7 2 5 F 6 2 7 9 5 F 6 C 3 4 7 9 3 3 7 2 7 D 0 A 0 A 0 A"

# 1. Perbaiki typo akibat kemiripan bunyi Morse
# V3 0 (...- ...-- -----) -> 3 0 (...-- -----)
# 5 U (..... ..-) -> 5 F (..... ..-.)
cleaned_output = morse_output.replace("V3 0", "3 0").replace("U", "F")

# 2. Hapus semua spasi agar menjadi satu string Hex yang utuh
hex_string = cleaned_output.replace(" ", "")

# 3. Ubah Hex menjadi format Bytes, lalu decode ke ASCII
flag_bytes = bytes.fromhex(hex_string)
flag = flag_bytes.decode('ascii', errors='ignore')

# 4. Tampilkan hasil
print(f"[+] Hex yang diperbaiki: {hex_string}")
print(f"[+] FLAG: {flag.strip()}")

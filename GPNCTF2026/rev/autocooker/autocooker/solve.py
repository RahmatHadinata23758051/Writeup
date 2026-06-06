# Copy output hex dari command 'p8 64' di atas ke dalam variabel ini
delicious_hex = "0a0a0a0a7ddfa94e5f9ffc2cf9b9ee5fd99dfeec8de92e5f8dff5e5f8f5ccc5f3decbe998d5ffe8dbc5fff5c3f5ffe1cb96e5f6c9999ce5f3e1dceef9e4eafde"

delicious = bytearray.fromhex(delicious_hex)
food = bytearray(64)

for i in range(64):
    b = delicious[i]
    
    # 1. Untrim (Karena trim melakukan 'and 0xf' pada indeks >= 61, 
    # bagian yang hilang tidak bisa ditebak dari bitwise, tapi flag asli biasanya diakhiri '}')
    # Kita abaikan dulu atau biarkan nilai apa adanya.
    
    # 2. Unfry (fry melakukan swap 4-bit / nibble jembatan: shl 4 | shr 4)
    b = ((b & 0x0F) << 4) | ((b & 0xF0) >> 4)
    
    # 3. Unsalt (salt melakukan xor dengan 0xAA)
    b ^= 0xAA
    
    food[i] = b

# 4. Unmix (mix membalikkan urutan array: RECIPE[i] = FOOD[63 - i])
recipe = food[::-1]

# Cetak flag yang berhasil di-decode
print("Flag:", recipe.decode(errors='ignore'))

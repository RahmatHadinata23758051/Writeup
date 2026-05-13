def decode_base999(encoded_str, byte_len):
    # 1. Pecah string menjadi blok 3 digit (Base-999 digits)
    chunks = [encoded_str[i:i+3] for i in range(0, len(encoded_str), 3)]
    
    # 2. Konversi dari Base-999 ke Integer Besar
    decimal_value = 0
    for chunk in chunks:
        decimal_value = decimal_value * 999 + int(chunk)
    
    # 3. Konversi Integer ke Bytes
    try:
        flag_bytes = decimal_value.to_bytes(byte_len, 'big')
        return flag_bytes.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"[Error] Gagal decode: {e}"

# Data dari output.txt
data = [
    (75, "001452364189848287923821742568954303648698985244216888407919381357574656595589327310217711904601016561079226903056403550476359808600659903252340182702873643487914166139407119810527154"),
    (33, "008254923251891373997947374522236000703540039225601391676590188700537882880174791"),
    (24, "002055539561030522839955247651389777708129343862662007097150")
]

print("=== Hasil Decoding ===")
for i, (length, enc_str) in enumerate(data):
    result = decode_base999(enc_str, length)
    print(f"String {i+1}: {result}")

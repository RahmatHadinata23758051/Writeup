def solve_lcg():
    # Spesifikasi yang diketahui
    M = 4294967296  # 2^32
    
    # Log token yang dicegat
    X = [
        3819650357, # Token 1 (X_0)
        11611408,   # Token 2 (X_1)
        1139973423, # Token 3 (X_2)
        3019417794, # Token 4 (X_3)
        3997094201, # Token 5 (X_4)
        3415034180  # Token 6 (X_5)
    ]

    # 1. Hitung selisih antar token
    D1 = (X[1] - X[0]) % M
    D2 = (X[2] - X[1]) % M

    # 2. Temukan Multiplier (A) menggunakan modular inverse
    # pow(base, -1, mod) adalah cara Python menghitung modular inverse
    A = (D2 * pow(D1, -1, M)) % M

    # 3. Temukan Increment (C)
    C = (X[1] - (A * X[0])) % M

    print("[+] LCG Ditembus!")
    print(f"[*] Multiplier (A) : {A}")
    print(f"[*] Increment (C)  : {C}")

    # Verifikasi apakah A dan C valid untuk semua token (sanity check)
    for i in range(len(X) - 1):
        assert X[i+1] == (A * X[i] + C) % M
    print("[+] Parameter divalidasi dengan sisa token lainnya. Berhasil!")

    # 4. Prediksi Token ke-7 (Master Override Key)
    X_6 = (A * X[-1] + C) % M
    print(f"\n[*] Token ke-7 (Mentah) : {X_6}")

    # 5. Format Flag sesuai instruksi:
    # "LNC26{TOKEN} (9 digits, pad with a leading zero)"
    token_str = str(X_6).zfill(9)
    flag = f"LNC26{{{token_str}}}"
    
    print(f"\n[🚀] FLAG FOUND: {flag}")

if __name__ == "__main__":
    solve_lcg()

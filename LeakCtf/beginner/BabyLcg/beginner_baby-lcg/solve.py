from Crypto.Util.number import long_to_bytes

# Data dari output.txt
m = 88044978735773602913395349457408066612245192322881563734438993831688084200491
s0 = 4452065008288242560629390669208864932242141417756588067313178112477164149842
s1 = 30356301725547557665274966292036883630163427635439138410477840356169747135880
s2 = 33330863090985168864945055645699247424789280002692545918305324950320521259312
ct = 8850041716144071587274828779665113489634774808247082181515445941038495956603515

# 1. Hitung pengali (a)
# (s2 - s1) = a * (s1 - s0)  (mod m)
diff_10 = (s1 - s0) % m
diff_21 = (s2 - s1) % m

# a = (s2 - s1) * inv(s1 - s0) mod m
a = (diff_21 * pow(diff_10, -1, m)) % m

# 2. Hitung increment (c)
c = (s1 - a * s0) % m

# 3. Hitung key (state berikutnya / s3)
key = (a * s2 + c) % m

# 4. Decrypt Flag (XOR)
flag_int = ct ^ key
flag = long_to_bytes(flag_int)

print(f"[+] Multiplier (a): {a}")
print(f"[+] Increment  (c): {c}")
print(f"[+] Key (s3)      : {key}")
print(f"\n[+] FLAG: {flag.decode()}")

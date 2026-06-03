from Crypto.Util.number import long_to_bytes

# The target ending string given in the challenge
S_str = "03081127692533913997381228658418928780421416188103339458770036280397929450297959557812089439331054492922876854076547798835969658432397983993314299716042752"
S = int(S_str)

# Modulus sizes
k = len(S_str)  # 152
mod_5 = 5**k

# Divide out the common factor of 2^152
numerator = S // (2**k)
exponent = 77777 - k

# Calculate the modular inverse of 2^77625 mod 5^152
val_mod_5 = (numerator * pow(2, -exponent, mod_5)) % mod_5

# Since a < 5^152 (or very close to it), val_mod_5 is likely our flag 'a'
# Let's try to decode it directly
flag = long_to_bytes(val_mod_5)
print(flag)

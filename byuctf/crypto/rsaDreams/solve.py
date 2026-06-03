# solve.py
import math
from Crypto.Util.number import long_to_bytes, inverse

# 1. Parameter eksak dari output.txt
c = 5074616349947930347771128443869249667723941019037011379843932659330729580197593522845748676276068149443504037403162962894625104017380398816152166168830833
n = 6452268004013779272669102227661703532150635430524568657091997086066784917218113937677647594597481724133073200003104968955173212323278046973034541033497147
e = 65537
hint = 161697499284577475400347684012866511237569864647822807778480533925514941939388

# 2. Kalkulasi Diskriminan: D = (p+q)^2 - 4n
D = hint**2 - 4 * n

# 3. Akar kuadrat eksak dari D untuk mendapatkan selisih (p - q)
diff = math.isqrt(D)

# 4. Evaluasi dan ekstraksi nilai p dan q
p = (hint + diff) // 2
q = (hint - diff) // 2

# Verifikasi faktorisasi otomatis
assert p * q == n, "[-] Error: Faktorisasi gagal!"

# 5. Eksekusi dekripsi RSA
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, n)

# 6. Ekstraksi format flag sesuai protokol
flag = long_to_bytes(m)
print(f"<FLAG>{flag.decode()}</FLAG>")

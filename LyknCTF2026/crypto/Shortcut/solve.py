import json
import hashlib
from Crypto.Util.number import long_to_bytes, GCD
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --- DATA DARI SERVER ---
data = {
  "N": "1189865343852471773069395469113572924480641038338018888079373496978577447575992848300928819755521182030670768391717374546888380512805243995093373204100013014380458624469428659765875752523718415657251368998263601503326556210003219967206063940353503211956888136162254733314901989993427052026712707754236067931472280522891306739865545061192557187594474875051185509807329675380153845965686108818740202849070288019123641795380616287245973720406328384769122055372401497",
  "e": "320726919524370925367292807213131544969176601757371110873481439886584305157650288985108594248994740664012502353527289171343608534178265248067926531618249986973214258362055873547949838235484056951502167210708249626994656028247977119990162870192528367261273935793048060865674621367429935176892090964525405305066540849167972743409829269180507558926563533115534403465211420828680403999018069977949265874454615711748676143401273610407500902708921022215059610187215919",
  "encrypted_flag": "733745028dd84e2f6281204fd8de3a813e65ede604ad849ab3dcfc95bd886519d4fc568875afac0837",
  "nonce": "be871e092aa0fa60506b0db5",
  "tag": "41bcd47b3490405b858e9e0f0acb4518",
  "leakage2": {"S": "2"}
}

N = int(data["N"])
e = int(data["e"])
ciphertext = bytes.fromhex(data["encrypted_flag"])
nonce = bytes.fromhex(data["nonce"])
tag = bytes.fromhex(data["tag"])
S = int(data["leakage2"]["S"])

# --- IMPLEMENTASI WIENER'S ATTACK ---
def continued_fractions(n, d):
    """Membuat ekspansi pecahan berlanjut dari n/d"""
    cf = []
    while d:
        q = n // d
        cf.append(q)
        n, d = d, n - q * d
    return cf

def convergents(cf):
    """Menghitung konvergen (k/d) dari pecahan berlanjut"""
    n0, d0 = cf[0], 1
    if len(cf) == 1:
        return [(n0, d0)]
    n1, d1 = cf[0] * cf[1] + 1, cf[1]
    conv = [(n0, d0), (n1, d1)]
    for i in range(2, len(cf)):
        ni = cf[i] * conv[i-1][0] + conv[i-2][0]
        di = cf[i] * conv[i-1][1] + conv[i-2][1]
        conv.append((ni, di))
    return conv

print("[*] Melakukan Wiener's Attack untuk mencari d, p, dan q...")
cf = continued_fractions(e, N)
convs = convergents(cf)

p, q, d = None, None, None

for k, d_cand in convs:
    if k == 0 or d_cand % 2 == 0:
        continue
    
    # Hitung kemungkinan phi
    phi_cand = (e * d_cand - 1) // k
    
    # Selesaikan persamaan kuadrat x^2 - (N - phi + 1)x + N = 0
    b = N - phi_cand + 1
    discr = b*b - 4*N
    if discr >= 0:
        import math
        # Cek akar sempurna
        isqrt_discr = math.isqrt(discr)
        if isqrt_discr * isqrt_discr == discr:
            p_cand = (b + isqrt_discr) // 2
            q_cand = (b - isqrt_discr) // 2
            if p_cand * q_cand == N:
                p, q, d = p_cand, q_cand, d_cand
                print(f"[+] Parameter ditemukan!")
                print(f"    p = {p}")
                print(f"    q = {q}")
                print(f"    d = {d}")
                break

if not p:
    print("[-] Gagal memulihkan p dan q melalui Wiener's Attack.")
    exit()

# --- REKONSTRUKSI PARAMETER RAHASIA ---
phi = (p - 1) * (q - 1)
g = GCD(p - 1, q - 1)
lambda_n = phi // g

# --- REKONSTRUKSI KUNCI AES ---
d_bytes = long_to_bytes(d)
V_int = d_bytes[:16]

H1 = hashlib.sha256(V_int).digest()
H2 = hashlib.sha256(long_to_bytes(S)).digest()
H3 = hashlib.sha256(long_to_bytes(lambda_n)).digest()

IKM = H1 + H2 + H3

hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b"FastLane-RSA-2024",
    info=b"FastLane-AES-Key"
)
aes_key = hkdf.derive(IKM)
print(f"[+] AES Key pulih: {aes_key.hex()}")

# --- DEKRIPSI AES-GCM ---
# Perhatikan bahwa di python cryptography, tag harus digabung di akhir ciphertext untuk AESGCM
full_ciphertext = ciphertext + tag
aesgcm = AESGCM(aes_key)

try:
    flag = aesgcm.decrypt(nonce, full_ciphertext, None).decode()
    print(f"\n[+] FLAG: {flag}")
except Exception as e:
    print(f"[-] Gagal melakukan dekripsi: {e}")

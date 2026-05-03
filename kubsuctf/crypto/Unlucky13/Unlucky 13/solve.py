import hashlib

# Data dari output.txt
n = 13658633037131788032351618427072247476717954542396408633560773884364554559070511401338131167308785959562652843354491812218130569318378376258845006015571936307529619165627684367938035500689095197148634390329808425228615805061358885887601807910577877331466810636357076781023936730357996997258012513541846157478488478454563307821991031194437503266795021183758263745762989760240683361817082008819321416765453826690538816962208131444601183340450621147225799934380535423737829891317625290259915071423282523846993193854126576514135696151799274710837198613476445017109884172011540789567531049972285279517155764888481047450059
e = 3
c = 58106402945252412885867908042116794819464305744971899578073020304067543548070807457178658563488157040731309267600804875202490191851964629071348907183348604959890636799938893288492152226256276862912678404321252232876509325092153164813635360471085498336853220078206620458027876601442698309483452313201963351276803179820555434275959791505894082437152805771101360567738286600728

# 1. Bypass Layer 3 (RSA Cube Root Attack)
# Fungsi pencari akar pangkat e (Integer Nth Root)
def find_invpow(x, n):
    high = 1
    while high ** n < x:
        high *= 2
    low = high // 2
    while low < high:
        mid = (low + high) // 2
        if mid ** n < x:
            low = mid + 1
        else:
            high = mid
    return low

m_int = find_invpow(c, e)

# Ubah integer m ke dalam bentuk bytes
layer2_bytes = m_int.to_bytes((m_int.bit_length() + 7) // 8, 'big')
print("[+] Layer 3 (RSA) berhasil didekripsi.")


# 2. Bypass Layer 2 (RC4 / Forgotten Cipher)
UNLUCKY_NUMBER = 13
secret = b"Unlucky" + str(UNLUCKY_NUMBER).encode()
fc_key = hashlib.sha256(secret).digest()[:16]

def forgotten_cipher(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

# Dekripsi layer 2 dengan memasukkannya kembali ke fungsi karena ia stream cipher simetris
layer1_bytes = forgotten_cipher(fc_key, layer2_bytes)
print("[+] Layer 2 (RC4) berhasil didekripsi.")


# 3. Bypass Layer 1 (Cursed PRNG XOR)
def cursed_prng(seed, length):
    state = seed
    stream = []
    for _ in range(length):
        state = (state * 1313 + 131313) % (2**32)
        stream.append(state & 0xFF)
    return bytes(stream)

# Lakukan operasi XOR kembali dengan keystream yang sama
FLAG = bytes(a ^ b for a, b in zip(layer1_bytes, cursed_prng(UNLUCKY_NUMBER, len(layer1_bytes))))

print("\n[!] FLAG DITEMUKAN:")
print(FLAG.decode('utf-8'))

import itertools

data = bytes.fromhex("1d090d07670f4404711b0c1e493202391c100640732b45056c0b26180e0b3e27130e5d0e")
keys = [b"icns", b"name", b"ttf", b"xy", b"lzma", b"KLZMA_DATA:", b"\x01", b"\x02", b"\x00", b"\x08"]

for c in itertools.combinations_with_replacement(keys, 3):
    res = []
    for i in range(len(data)):
        val = data[i]
        for k in c:
            val ^= k[i % len(k)]
        res.append(chr(val))
    s = "".join(res)
    if s.startswith("tjctf{"):
        print(c, s)


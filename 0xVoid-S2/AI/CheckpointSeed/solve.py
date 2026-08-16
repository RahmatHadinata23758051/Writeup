import json, random

data=json.load(open("checkpoint.json"))

cipher=bytes.fromhex(data["cipher_hex"])

r=random.Random(data["seed"])

plain=bytes([
    b ^ r.randrange(256)
    for b in cipher
])

print(plain.decode())

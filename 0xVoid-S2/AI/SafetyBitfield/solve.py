import json

data=json.load(open("safety_bits.txt"))

data=sorted(data,key=lambda x:x["token_id"])

bits="".join("1" if x["allowed"] else "0" for x in data)

print("[+] bits:")
print(bits)
print("[+] length:",len(bits))

for rev in [False,True]:
    b=bits[::-1] if rev else bits

    out=""
    for i in range(0,len(b),8):
        out+=chr(int(b[i:i+8],2))

    print("reverse =",rev,repr(out))

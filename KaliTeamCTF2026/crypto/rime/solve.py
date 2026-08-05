#!/usr/bin/env python3
from pwn import *
from collections import Counter
import os,re

HOST="chall.kali-team.online"
PORT=10033

context.log_level="info"


def parse(out):

    fp=re.search(
        r"fingerprint : ([0-9a-f]+)",
        out
    ).group(1)

    digest=re.search(
        r"digest      : ([0-9a-f]+)",
        out
    ).group(1)

    com=re.search(
        r"commitments : ([0-9a-f]+)",
        out
    ).group(1)

    R=re.search(
        r"R           : ([0-9a-f]+)",
        out
    ).group(1)

    z=re.search(
        r"z           : ([0-9a-f]+)",
        out
    ).group(1)

    return fp,digest,com,R,z


def parse_commitment(c):

    b=bytes.fromhex(c.strip())

    points=[]

    i=0
    while i < len(b):

        signer=b[i]

        # skip id
        i+=1

        if i+33 > len(b):
            break

        D=b[i:i+33]
        i+=33

        if i+33 > len(b):
            break

        E=b[i:i+33]
        i+=33

        points.append(
            (
                signer,
                D.hex(),
                E.hex()
            )
        )

    return points



io=remote(HOST,PORT)
io.recvuntil(b"rime$")


all_D=[]
all_E=[]
sigs=[]


for i in range(32):

    # random valid hex input
    data=os.urandom(1024).hex()

    io.sendline(
        b"attest "+data.encode()
    )

    out=io.recvuntil(b"rime$").decode()

    print("[+] got",i)

    fp,digest,com,R,z=parse(out)

    sigs.append(
        {
            "digest":digest,
            "R":R,
            "z":z
        }
    )


    pts=parse_commitment(com)

    for signer,D,E in pts:
        print(
            " signer",
            signer,
            "D",
            D[:10],
            "E",
            E[:10]
        )

        all_D.append(D)
        all_E.append(E)



print("\n==== CHECK DUPLICATE ====")


d=Counter(all_D)
e=Counter(all_E)


print("D duplicate:")
for x,n in d.items():
    if n>1:
        print(x,n)


print("E duplicate:")
for x,n in e.items():
    if n>1:
        print(x,n)


open("sigs.txt","w").write(
    str(sigs)
)

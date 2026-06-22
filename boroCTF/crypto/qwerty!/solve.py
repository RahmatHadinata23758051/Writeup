#!/usr/bin/env python3

s = r"?AEAGJ8NJF,\0[d5JcE-"

def rot47(x):
    out = ""
    for c in x:
        o = ord(c)
        if 33 <= o <= 126:
            out += chr(33 + ((o - 33 + 47) % 94))
        else:
            out += c
    return out

rows = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
    "~!@#$%^&*()_+",
    "QWERTYUIOP{}|",
    'ASDFGHJKL:"',
    "ZXCVBNM<>?",
]

def shift_left(x):
    out = ""
    for c in x:
        done = False
        for row in rows:
            if c in row:
                i = row.index(c)
                out += row[i - 1] if i > 0 else c
                done = True
                break
        if not done:
            out += c
    return out

stage1 = rot47(s)
stage2 = shift_left(stage1)

print("[rot47] ", stage1)
print("[qwerty]", stage2)

flag = stage2.replace("boroctf", "boroCTF").replace(")", "_").replace("]", "}")
print("[flag]  ", flag)

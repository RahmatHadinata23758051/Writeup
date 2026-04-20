#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Recovered obfuscated fragments from memory (one per colony module)
OBFUSCATED = {
    "mercury": "``7?(9/(#``kuo``l>>oho8b<9n;",
    "venus": "``,?4/)``huo``;8n>ljjo>8kh",
    "earth": "``?;(.2``iuo``okk9kii?<8<>",
    "mars": "``7;()``nuo``?m>cm9k>8>?l",
    "jupiter": "``0/*3.?(``ouo``cl8?hm8jbcbo?8lk",
}

# Challenge artifacts (inlined so solver still works after cleanup)
IV_HEX = "98ba2cc716d1e9fb865428b59fae7ead"
PAYLOAD_HEX = "63d53b74b9f15ea0c8a9f6f005f6ef6d22fedf17f6fcb4b5e6a0f0a80522d250"


def deobfuscate(s: str) -> str:
    return "".join(chr(ord(c) ^ 0x5A) for c in s)


def extract_hex_fragment(decoded: str) -> str:
    # decoded format example: ::venus::2/5::ab4d6005db12
    return decoded.split("::")[-1]


def main() -> None:
    decoded = {k: deobfuscate(v) for k, v in OBFUSCATED.items()}

    # Order from i/5 marker found in decoded strings
    # 1/5 mercury, 2/5 venus, 3/5 earth, 4/5 mars, 5/5 jupiter
    key_hex = (
        extract_hex_fragment(decoded["mercury"])
        + extract_hex_fragment(decoded["venus"])
        + extract_hex_fragment(decoded["earth"])
        + extract_hex_fragment(decoded["mars"])
        + extract_hex_fragment(decoded["jupiter"])
    )

    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(IV_HEX)
    ct = bytes.fromhex(PAYLOAD_HEX)

    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    flag = unpad(pt, 16).decode()

    print("[+] Recovered key:", key_hex)
    print("[+] Flag:", flag)


if __name__ == "__main__":
    main()

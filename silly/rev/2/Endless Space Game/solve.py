#!/usr/bin/env python3
import base64
import hashlib
from Crypto.Cipher import AES


def decrypt(cipher_text: str, password: str, salt: bytes = b"sillysalting") -> str:
    raw = base64.b64decode(cipher_text)
    dk = hashlib.pbkdf2_hmac("sha1", password.encode(), salt, 100000, dklen=48)
    key, iv = dk[:32], dk[32:48]
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(raw)
    pad = pt[-1]
    return pt[:-pad].decode()


if __name__ == "__main__":
    cipher = "SB1WutP8DlpgdkPnQPf7Jre3aL8UfKVcOIvokdpWCbs="
    password = "dEi0245RHYB12ic"
    flag = decrypt(cipher, password)
    print(flag)

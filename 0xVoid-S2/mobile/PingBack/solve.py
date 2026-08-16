#!/usr/bin/env python3
import hashlib
import subprocess
import sys
import zipfile
from pathlib import Path

APK_PATH = Path("PingBack.apk")
ASSET_NAME = "assets/signal.enc"

# Nilai ini hasil reverse dari UnlockReceiver:
# getExpectedAuth() = "SYNC-2026".concat("-PING")
# getExpectedSeq()  = 12 - 1
AUTH = "SYNC-2026-PING"
SEQ = 11

# IV diinisialisasi di <clinit> via fill-array-data payload.
IV = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")


def pkcs7_unpad(data: bytes) -> bytes:
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-pad]


def read_signal() -> bytes:
    # Bisa membaca dari APK langsung, jadi tidak wajib unzip dulu.
    with zipfile.ZipFile(APK_PATH, "r") as zf:
        return zf.read(ASSET_NAME)


def decrypt_with_python_libs(key: bytes, iv: bytes, ct: bytes) -> bytes | None:
    # Prefer cryptography kalau ada.
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return dec.update(ct) + dec.finalize()
    except Exception:
        pass

    # Fallback PyCryptodome kalau environment user punya Crypto.
    try:
        from Crypto.Cipher import AES

        return AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    except Exception:
        return None


def decrypt_with_openssl(key: bytes, iv: bytes, ct: bytes) -> bytes:
    proc = subprocess.run(
        [
            "openssl",
            "enc",
            "-d",
            "-aes-128-cbc",
            "-K",
            key.hex(),
            "-iv",
            iv.hex(),
        ],
        input=ct,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    # openssl sudah menghapus PKCS#7 padding secara default.
    return proc.stdout


def main() -> None:
    material = f"{AUTH}{SEQ}".encode()
    key = hashlib.sha1(material).digest()[:16]
    ct = read_signal()

    pt = decrypt_with_python_libs(key, IV, ct)
    if pt is not None:
        pt = pkcs7_unpad(pt)
    else:
        pt = decrypt_with_openssl(key, IV, ct)

    flag = pt.decode("utf-8")
    print(flag)
    print()
    print("Intent untuk trigger receiver:")
    print(
        "adb shell am broadcast "
        "-a com.pingback.ACTION_UNLOCK "
        "-n com.pingback.app/.UnlockReceiver "
        f"--es auth {AUTH} --ei seq {SEQ}"
    )
    print("adb logcat -s PingBack:D")


if __name__ == "__main__":
    if not APK_PATH.exists():
        sys.exit(f"missing {APK_PATH}")
    main()

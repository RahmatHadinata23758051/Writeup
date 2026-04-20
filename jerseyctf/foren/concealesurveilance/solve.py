#!/usr/bin/env python3
import base64

fragments_b64 = {
    "frag1": "amN0Znt0aDNfY29tbW9kMHIzcw",       # test.ps1 description
    "frag2": "dHJAdGVkXyFudDA=",               # telemetry.ps1 URI token
    "frag3": "X2hAdmVfaW5mMWw",               # fake Windows Update task description
    "frag4": "X3RoM19hcG9sbDAhfQ==",           # PSReadLine / WMI persistence description
}

def b64d(s: str) -> str:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode((s + pad).encode()).decode(errors="replace")

parts = [b64d(fragments_b64[f"frag{i}"]) for i in range(1, 5)]
flag = "".join(parts)

print("[+] Decoded fragments:")
for i, p in enumerate(parts, 1):
    print(f"  {i}. {p}")

print("\n[+] Flag:")
print(flag)

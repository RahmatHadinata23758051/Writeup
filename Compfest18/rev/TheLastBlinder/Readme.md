# The Last Bitbender

## Category

Reverse Engineering

## Description

```
who knew Aang could bend bits too?
```

The challenge gives a small Windows executable and a remote service. The service sends a 16-byte hexadecimal request and expects the correct 16-byte hexadecimal response.

Final flag:

```
COMPFEST18{0nly_th3_av4t4r_m4st3r3d_4ll_th3m_b1ts_V3oxYBru0HXUb1rA}
```

## 1. Initial Triage

First, check the binary type and some useful strings.

```bash
file chall.exe
strings -a chall.exe
objdump -x chall.exe
```

The file is a very small PE32 executable:

```
PE32 executable for MS Windows 4.00 (console), Intel i386, 2 sections
```

Interesting imports:

```
msvcrt.dll: memset, memcpy, memcmp, printf
kernel32.dll: VirtualAlloc, VirtualFree
```

Interesting strings:

```
self-test ok
self-test failed
```

The binary is small, but it is not just a normal 32-bit validator. The code uses far returns and segment selector changes to switch between 32-bit and 64-bit execution. This is the classic Heaven's Gate trick.

The important pattern is:

```asm
mov ax, cs
add eax, 0x10
push eax
call next
add dword [esp], 5
retf
```

Later stages use the reverse form with `sub eax, 0x10` and another `retf` to return to 32-bit mode.

So the binary flow is approximately:

```
32-bit loader
  -> switch to 64-bit stage
  -> decrypt next payload
  -> switch back to 32-bit stage
  -> switch to 64-bit stage again
  -> final 32-bit output stage
```

## 2. Payload Stages

After dumping/decrypting the payload stages, the validator becomes a small arithmetic transformation over 16 input bytes.

The input is split into two little-endian 64-bit integers:

```
a = input[0:8]
b = input[8:16]
```

The first 64-bit word is XORed with a constant:

```
a ^= 0xA6F1C0D93B5E2748
```

Then the binary performs three logical stages.

### Stage 1: 32-bit arithmetic stage

The 32-bit stage updates `a` using the low 32 bits of `a` and `b`, rotates `b`, then XORs both values.

Equivalent Python:

```python
a = (a + ((a & 0xffffffff) * (b & 0xffffffff))) & 0xffffffffffffffff
b = rol64(b, 13)
a ^= b
```

### Stage 2: 64-bit arithmetic stage

The next 64-bit stage mixes both words with addition, rotation, and multiplication.

Equivalent Python:

```python
b = (b + a) & 0xffffffffffffffff
b = rol64(b, 29)
b = (b * 0xFF51AFD7ED558CCD) & 0xffffffffffffffff
a = (a + b) & 0xffffffffffffffff
a = rol64(a, 17)
```

### Stage 3: final output stage

The final 32-bit stage writes 16 output bytes:

```
out0 = a ^ b
out1 = a + b
```

Both are written as little-endian 64-bit values.

So the challenge is not asking us to recover a static password. The remote gives a random request, and we have to compute the forward transformation.

## 3. Reimplemented Transform

The full transform is:

```python
MASK64 = (1 << 64) - 1
K0 = 0xA6F1C0D93B5E2748
MUL2 = 0xFF51AFD7ED558CCD


def rol64(x, n):
    return ((x << n) & MASK64) | (x >> (64 - n))


def bitbend(inp):
    a = int.from_bytes(inp[:8], 'little') ^ K0
    b = int.from_bytes(inp[8:], 'little')

    a = (a + ((a & 0xffffffff) * (b & 0xffffffff))) & MASK64
    b = rol64(b, 13)
    a ^= b

    b = (b + a) & MASK64
    b = rol64(b, 29)
    b = (b * MUL2) & MASK64
    a = (a + b) & MASK64
    a = rol64(a, 17)

    return (a ^ b).to_bytes(8, 'little') + ((a + b) & MASK64).to_bytes(8, 'little')
```

## 4. Solver

Save this as `solve.py`.

```python
#!/usr/bin/env python3
import argparse
import re
import select
import socket
from struct import pack, unpack

MASK64 = (1 << 64) - 1
K0 = 0xA6F1C0D93B5E2748
MUL2 = 0xFF51AFD7ED558CCD
REQUEST_RE = re.compile(rb'request:\s*([0-9a-fA-F]{32})', re.I)


def rol64(x: int, n: int) -> int:
    return ((x << n) & MASK64) | (x >> (64 - n))


def bitbend(inp: bytes) -> bytes:
    if len(inp) != 16:
        raise ValueError('input must be exactly 16 bytes')

    a = unpack('<Q', inp[:8])[0] ^ K0
    b = unpack('<Q', inp[8:])[0]

    a = (a + ((a & 0xffffffff) * (b & 0xffffffff))) & MASK64
    b = rol64(b, 13)
    a ^= b

    b = (b + a) & MASK64
    b = rol64(b, 29)
    b = (b * MUL2) & MASK64
    a = (a + b) & MASK64
    a = rol64(a, 17)

    return pack('<QQ', a ^ b, (a + b) & MASK64)


def solve_one(req_hex: str) -> str:
    req_hex = req_hex.strip()
    if not re.fullmatch(r'[0-9a-fA-F]{32}', req_hex):
        raise ValueError('request must be exactly 32 hex characters')
    return bitbend(bytes.fromhex(req_hex)).hex()


def remote(host: str, port: int, timeout: float = 20.0) -> int:
    s = socket.create_connection((host, port), timeout=10)
    buf = b''
    answered = set()

    with s:
        s.setblocking(False)
        idle = 0.0

        while True:
            r, _, _ = select.select([s], [], [], 0.5)

            if not r:
                idle += 0.5
                if idle >= timeout:
                    print('[!] timeout')
                    return 1
                continue

            idle = 0.0
            data = s.recv(4096)
            if not data:
                return 0

            print(data.decode(errors='ignore'), end='')
            buf += data

            for m in REQUEST_RE.finditer(buf):
                req = m.group(1).lower()
                if req in answered:
                    continue

                ans = solve_one(req.decode()).encode()
                s.sendall(ans + b'\n')
                answered.add(req)
                print(f'\n[>] response: {ans.decode()}')

            if len(buf) > 32768:
                buf = buf[-2048:]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('host', nargs='?')
    ap.add_argument('port', nargs='?', type=int)
    ap.add_argument('-t', '--target', help='solve one 32-hex request offline')
    args = ap.parse_args()

    if args.target:
        print(solve_one(args.target))
        return 0

    if args.host and args.port:
        return remote(args.host, args.port)

    ap.print_help()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
```

## 5. Testing Locally

Example request from the service:

```
ee19a09be3eb777fba7330e7060377b1
```

Run:

```bash
python3 solve.py -t ee19a09be3eb777fba7330e7060377b1
```

Output:

```
3bb532fac311a160bbcacc02e4e1398b
```

## 6. Getting the Flag

Run the solver against the challenge instance:

```bash
python3 solve.py HOST PORT
```

The service sends a request:

```
request: 0256da08afb894ca54ffb82476653183
response:
```

The solver computes and sends:

```
88705e55ef8eab2314759e65efee5354
```

After the response is accepted, the service returns:

```
ok
COMPFEST18{0nly_th3_av4t4r_m4st3r3d_4ll_th3m_b1ts_V3oxYBru0HXUb1rA}
```

## Flag

```
COMPFEST18{0nly_th3_av4t4r_m4st3r3d_4ll_th3m_b1ts_V3oxYBru0HXUb1rA}
```

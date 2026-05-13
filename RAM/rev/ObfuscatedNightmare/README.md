# CTF Writeup — Obfuscated Nightmare

**Event:** Not provided  
**Category:** Rev  
**Difficulty:** Unknown  
**Flag:** `RMCTF{5p34k1n6_1n_c0d3!}`

---

## Challenge Description

> We have found the application responsible for processing data within the Gibson itself. However, analysis conducted by our team has been inconclusive and it is not clear how this application works. Can you reverse the application and find away to see inside the Gibson's thoughts?

**Target:** `10.42.5.10:1337`

---

## Reconnaissance

### Step 1 — Triage the Binary

The challenge only shipped a stripped 64-bit ELF named `chall`.

Quick checks showed:
- Rust binary
- PIE enabled
- No symbols
- The program prompts for input, then prints either `Wrong!` or `Welcome!`

Running it locally immediately suggested that this was not a normal password checker:

```bash
./chall
AI Key:
```

The input also behaved strangely during debugging. It was not being compared as a plain string. Instead, the binary was parsing data in fixed 3-byte chunks and feeding those chunks into an internal interpreter.

### Step 2 — Recognize the VM

Static analysis in Ghidra and `objdump` showed that the program builds and executes a tiny custom VM.

Two details made that clear:
- Input is parsed in groups of 3 bytes
- A large static blob in `.rodata` is interpreted as bytecode

That static program was responsible for printing the visible strings:
- `AI Key:`
- `Welcome!`
- `Wrong!`

So the challenge was really split into two parts:
1. Satisfy the built-in boot/validator bytecode
2. Feed the VM a second-stage program that opens and prints `/flag.txt`

---

## Exploitation

### Step 3 — Recover the AI Key

The first stage does not check an ordinary password. It runs a short bytecode validator over the beginning of our input and branches to either `Welcome!` or `Wrong!`.

After tracing the branch conditions in GDB and mapping the VM instructions, the required leading bytes worked out to:

```python
b"API-@d!!?@??AUUU"
```

The important part is the prefix `API-`. Several later bytes are effectively filler in this path, as long as they do not break the parser.

Testing that key locally:

```bash
python3 - <<'PY'
import subprocess
p = subprocess.run(
    ["./chall"],
    input=b"API-@d!!?@??AUUU",
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
print(p.stdout.decode("latin1"))
PY
```

Output:

```text
AI Key: Welcome!
```

### Step 4 — Reverse the VM Instruction Set

The next step was understanding enough opcodes to write our own VM program.

The core instructions used in the final solve were:

| Opcode form | Meaning |
|---|---|
| `reg, 0x21, imm` | load immediate into register |
| `reg, 0x24, 0x00` | push register byte onto VM stack |
| `dst, 0x26, src` | move register |
| `sysno, 0x41, dst` | perform VM syscall, store return value in `dst` |
| `0x00, 0x42, 0x00` | halt |

The useful syscalls were:

| Syscall | Meaning |
|---|---|
| `1` | read from opened file into VM memory |
| `2` | write VM memory to stdout |
| `3` | open file path from VM memory |

That was enough. I did not need to fully recover every opcode in the VM, only the subset needed for file I/O.

### Step 5 — Build a Second-Stage Payload

The second stage pushes `/flag.txt` onto the VM stack, opens it, reads the contents into VM memory, then writes the bytes back to stdout.

The logic is:

```text
push "/flag.txt"
r0 = sp
r1 = len("/flag.txt")
sys3 -> open(path)

r0 = 0
r1 = 0xff
sys1 -> read(fd, mem[0], 0xff)

r0 = 0
r1 = bytes_read
sys2 -> write(mem[0], bytes_read)

halt
```

In Python, the payload builder looked like this:

```python
def li(reg, val):
    return bytes([reg, 0x21, val])

def push(reg):
    return bytes([reg, 0x24, 0x00])

def mov(dst, src):
    return bytes([dst, 0x26, src])

def sysc(num, dst=0):
    return bytes([num, 0x41, dst])
```

The final exploit simply sent:
- the valid AI key
- followed immediately by the second-stage VM program

When run against the service, the VM opened `/flag.txt` and printed the contents directly.

### Step 6 — Extract the Flag

Running the exploit against the remote service produced:

```text
RMCTF{5p34k1n6_1n_c0d3!}
```

---

## Flag

```text
RMCTF{5p34k1n6_1n_c0d3!}
```

---

## Technical Summary

| # | Finding | Detail |
|---|---|---|
| 1 | Custom bytecode VM | The binary interprets both static and attacker-controlled 3-byte instructions |
| 2 | Staged execution | A short built-in validator gates access to a second, more powerful execution path |
| 3 | File I/O exposed inside VM | The VM provides enough syscalls to open, read, and print `/flag.txt` |
| 4 | Partial key checking | The accepted AI key is constrained only in specific positions, making a printable working key possible |

---

## Remediation

1. Do not expose interpreter-like functionality to untrusted input unless it is heavily sandboxed.
2. Avoid bundling sensitive file access primitives into attacker-reachable VM/syscall handlers.
3. If staged validation is required, do not rely on obscurity of custom bytecode as the main defense.
4. Strip debugability where possible, but more importantly design the program so full reversal still does not expose privileged file access.

---

## Tools Used

- `file`, `checksec`, `strings`, `readelf`, `objdump`
- `gdb`
- Ghidra
- Python

---

## Attack Flow

```text
Inspect binary
      │
      ▼
Notice input is parsed as 3-byte VM instructions
      │
      ▼
Reverse static validator bytecode
      │
      ▼
Recover valid AI key: API-...
      │
      ▼
Reverse enough VM opcodes/syscalls for file I/O
      │
      ▼
Build second-stage bytecode:
  push "/flag.txt"
  open
  read
  write
  halt
      │
      ▼
Send key + stage payload
      │
      ▼
Service prints: RMCTF{5p34k1n6_1n_c0d3!}
```

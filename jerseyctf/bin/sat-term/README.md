# CTF Writeup — sat-term

**Event:** JerseyCTF  
**Category:** PWN / Binary Exploitation  
**Difficulty:** Medium  
**Flag:** `jctf{k3rbal_sp4ce_pr0gram_but_m4ke_it_b1nex}`

---

## Challenge Description

> Wow!! Take a look at this! We just gained access to a terminal managing a satellite up in orbit right now. Do you think the server communicating with that satellite is vulnerable?

**Service:** `nc sat-term.aws.jerseyctf.com 5000`  
**Given files:** `satterm`, `libc.so.6`, `ld-linux-x86-64.so.2`

---

## Reconnaissance

### Step 1 — Basic Binary Analysis

```bash
file satterm
checksec --file=satterm
ldd satterm
```

Important points:
- 64-bit ELF, dynamically linked
- `Canary: ON`
- `NX: ON`
- `PIE: OFF`
- `Full RELRO`

`PIE OFF` is useful because global addresses are fixed.

### Step 2 — Reverse Important Functions

Using `objdump`/`nm`, key functions are:
- `main`
- `operation_status`
- `operation_settings`
- `operation_diagnose`
- `initialize_operations`

The program uses `getcontext / makecontext / setcontext` to switch between command handlers.

### Step 3 — Bug Hunting

In `operation_settings`, this line is the core bug:

- `scanf("%lu", &nav_data.sync_ms)`

But `sync_ms` is only 2 bytes (`uint16_t`) inside `nav_data`.

So writing `%lu` (8-byte write) overflows into adjacent global memory and partially overwrites the global pointer `contexts`.

---

## Exploitation

### Step 4 — Memory Corruption Primitive

`nav_data` is in `.bss`, and `contexts` is right after it.

By controlling `DOWNLINK SYNCHRONIZATION MS`, we can corrupt low 4 bytes of `contexts`, then point it to controlled data inside global `input` buffer.

### Step 5 — Fake `ucontext_t` + `setcontext` Control

When command `STATUS` is chosen, program does:
- read `contexts[idx]`
- call `setcontext(contexts[idx])`

Since `contexts` now points to our fake structure, we control RIP/RDI/RSI/RDX via glibc `setcontext` restore layout.

### Step 6 — Stage 1 Leak libc

We build fake context for:
- `RIP = puts@plt`
- `RDI = puts@got`

Then return to `operation_status`, parse leak, and compute:
- `libc_base = leaked_puts - libc.sym['puts']`

### Step 7 — Stage 2 Command Execution

Build second fake context for:
- `RIP = execve@libc`
- `RDI = "/bin/sh"`
- `RSI = argv` where argv = `["/bin/sh", "-c", "cat /app/internal_satellite_comm.log; ...", NULL]`

This executes shell command and prints the flag.

---

## Flag

```txt
jctf{k3rbal_sp4ce_pr0gram_but_m4ke_it_b1nex}
```

---

## Vulnerability Summary

| # | Technique | Detail |
|---|---|---|
| 1 | Out-of-bounds write | `%lu` written into 2-byte field in `operation_settings` |
| 2 | Context hijack | Corrupted `contexts` pointer gives control over `setcontext` target |
| 3 | RCE via libc | Fake `ucontext_t` used to call `puts` (leak) and `execve` (command execution) |

---

## Tools Used

- `checksec`, `file`, `ldd`
- `objdump`, `readelf`, `nm`
- `gdb` / `pwntools`

---

## Attack Flow

```text
SETTINGS (%lu overflow)
        │
        ▼
overwrite global contexts pointer
        │
        ▼
setcontext(fake_ucontext in input buffer)
        │
        ├─ Stage 1: puts(puts@got) → leak libc
        │
        └─ Stage 2: execve("/bin/sh", ["/bin/sh","-c","cat ..."], NULL)
                              │
                              ▼
                            FLAG
```

---

## Installation

```bash
# Activate your venv
source /home/nata/ctf_env/bin/activate

# Run solver
python3 solve_sat_term.py
```

Optional:

```bash
python3 solve_sat_term.py HOST=sat-term.aws.jerseyctf.com PORT=5000
```

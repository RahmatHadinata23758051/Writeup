# CTF Writeup — Silent Signer

**Event:** THCON 2026  
**Category:** Reverse Engineering  
**Difficulty:** Medium  
**Flag:** `THC{int3_s3nt_u_h3r3_3bpf_t00k_1t_fr0m_th3r3!!!}`

---

## Challenge Description

> S.N.A.F.U. agents recovered sst-fwsign from a compromised workstation inside the SST Dynamics factory. It appears to be part of the firmware signing pipeline that M4terM4xima uses to flash compromised firmware onto the robots. Our field analysts tried attaching a debugger: each time, the validation fails. Reverse the binary and recover the signing token it accepts.

**File:** `sst-fwsign`

---

## Reconnaissance

### Step 1 — Identify the Binary

The challenge ships as a single stripped ELF:

```bash
file sst-fwsign
checksec --file=sst-fwsign
strings -a sst-fwsign | grep -E "token|Authorization|Signing|Usage"
```

That gives a few useful clues right away:

- It is a 64-bit Linux executable
- The binary is stripped, so there are no function names to rely on
- It prints:
  - `sst-fwsign v1.4.2 -- SST Dynamics Firmware Signing Service`
  - `Error: invalid token length.`
  - `Authorization failed. Token not recognized.`
  - `Signing key released. Batch authorized.`

The length check is the first easy win: the accepted token must be exactly **48 bytes**.

### Step 2 — Find the Validator

Following the usage string in the disassembly leads to the function that handles the command-line token.

The interesting part looked like this:

```asm
call signal
call strlen
cmp  rax, 0x30
jne  invalid_length
...
call fcn.00403e60
```

That helper was suspicious for one reason: it was almost empty except for an `int3`.

```asm
00403e60:
    push r12
    mov  rax, rsi
    mov  r12, rdi
    int3
    pop  r12
    ret
```

So the real validation logic was not happening in normal control flow at all. The process was deliberately trapping itself and relying on something else to decide the result.

---

## Anti-Debug Design

### Step 3 — Understand the Parent/Child Split

Looking earlier in the same function shows a `fork()`. The child calls:

```asm
ptrace(PTRACE_TRACEME, ...)
raise(SIGSTOP)
```

The parent then waits for stops and interacts with the child through `ptrace`.

That explains the challenge note: attaching a debugger breaks validation because the binary already expects to be the tracer. It is doing its own single-step and register handling.

### Step 4 — See What the Parent Really Does

The parent branch waits for `SIGTRAP`, grabs the register state with `PTRACE_GETREGSET`, performs some work, and writes a result back to the child with `PTRACE_POKEDATA`.

At this point it looked less like a classic anti-debug trick and more like a tiny execution environment. The child raises the trap, the parent computes a value, and the child reads the result from a global slot.

That still left one question: where does the computation itself live?

---

## Hidden eBPF Payload

### Step 5 — Recover the Embedded Object

The native binary contains a large encrypted blob. Before loading it, the program derives an 8-byte XOR key from three qwords stored in `.rodata`:

```asm
mov rax, [0x448988]
mov rdx, [0x448978]
xor rdx, rax
xor rax, [0x448980]
sub ...
xor ..., 0x4141414141414141
```

Decrypting the blob with that derived key reveals an **ELF64-BPF** object.

Once decoded, its sections become readable:

- `uprobe/fw_commit`
- `tp/syscalls/sys_enter_ptrace`
- `.maps`

That was the turning point. The binary is not just tracing itself for fun; it is loading eBPF programs and using them as part of the token check.

### Step 6 — Reverse the Two eBPF Programs

There are two relevant programs:

1. `integrity_watch`
2. `fw_verify`

`integrity_watch` runs on `sys_enter_ptrace` and fills a map called `fw_kdf` with six 64-bit constants if ptrace activity matches the expected flow.

`fw_verify` is attached as a uprobe and performs the real token validation. It processes six 8-byte blocks from the 48-byte token.

The core logic per block is:

```c
state ^= current_block;
tmp = fw_kdf[i] * state;
tmp = rol64(tmp, 13);
if (tmp != target[i]) fail;
acc ^= target[i];
```

The six comparison constants embedded in `fw_verify` are:

```text
0x66185fcb3af43c42
0xfb9181fc9d741ac9
0xf6f76d94d5f19c7c
0x9623be0fa7985447
0xc801d5b2ee724650
0x9faaf86a914846ee
```

The `fw_kdf` map values are seeded by `integrity_watch`, and the per-round XOR masks come from the native binary.

---

## Solving the Token

### Step 7 — Invert the Transformation

Each round is invertible because the multiplication uses odd 64-bit constants, which have modular inverses modulo `2^64`.

Let:

- `K[i]` be the native 64-bit mask for block `i`
- `M[i]` be the per-round multiplier from `fw_kdf`
- `T[i]` be the target constant from the eBPF verifier
- `A` be the running accumulator

Then:

```text
lane   = ror64(T[i], 13) * inv(M[i]) mod 2^64
block  = K[i] ^ ror64(A ^ lane, 7)
A     ^= T[i]
```

Applying that across all six rounds reconstructs the six 8-byte chunks of the token:

```text
THC{int3
_s3nt_u_
h3r3_3bp
f_t00k_1
t_fr0m_t
h3r3!!!}
```

Joined together:

```text
THC{int3_s3nt_u_h3r3_3bpf_t00k_1t_fr0m_th3r3!!!}
```

---

## Solver

The final solver is in [`solve.py`](/home/nata/ctf/THCON2026/rev/silentsigner/solve.py). It extracts the constants from the binary and reconstructs the token directly.

Run it with:

```bash
source /home/nata/ctf_env/bin/activate
python solve.py
```

Output:

```text
THC{int3_s3nt_u_h3r3_3bpf_t00k_1t_fr0m_th3r3!!!}
```

---

## Flag

```text
THC{int3_s3nt_u_h3r3_3bpf_t00k_1t_fr0m_th3r3!!!}
```

---

## Why This Challenge Was Nice

This one mixed several ideas without turning into guesswork:

- a stripped ELF with just enough strings to anchor the analysis
- a self-tracing anti-debug setup built around `int3`
- an encrypted embedded eBPF object
- a clean, reversible arithmetic transform once the moving parts were mapped

The anti-debugging layer looked noisy at first, but the moment the embedded BPF object was recovered, the challenge became much more structured. From there it was just a matter of modeling the six rounds and running the math backwards.

# TURING'S CURSE — Reverse Engineering Writeup

## Challenge Info

**Title:** TURING'S CURSE
**Category:** Reverse Engineering
**Flag format:**

```
0xV01D{...}
```

Challenge description hints that the binary contains many fake names/flags and that the real solution cannot be obtained by simply running strings or brute forcing. The intended path is to understand the transformation applied to the input and reverse it properly.

## Initial Recon

First, check the binary type:

```bash
file void
```

Result:

```
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

The binary is stripped and PIE-enabled, so symbol names are not available and addresses are randomized at runtime.

Basic hardening check:

```bash
checksec --file=void
```

The important point is that this is a native ELF binary and should be treated as a reverse engineering challenge, not a simple string search challenge.

## Decoy Flags

Running strings shows many flag-like values:

```bash
strings void | grep -i V01D
```

Example decoys include:

```
0xV01D{1mp0ss1bl3_p4th_r34ch3d_gh0st}
0xV01D{th1s_1s_n0t_th3_r34l_0n3_s0rry}
0xV01D{d3c0y_fl4g_th3_v01d_l4ughs_x0}
```

These are fake. The challenge description already warns that the obvious answer is not the real one.

There is also a XOR-decoded decoy:

```
0xV01D{K1ll_7h3_CUR53_57R1NG}
```

Submitting or testing these values does not unseal the binary.

## Program Behavior

When executed, the program asks for a name/input. The expected format is:

```
0xV01D{<payload>}
```

The actual validated payload length is 32 bytes, so the full flag length is:

```
len("0xV01D{") + 32 + len("}") = 40
```

The real validation logic extracts the 32-byte payload inside the braces and applies a custom transformation before comparing the result against a fixed target state.

## Anti-Debugging

The binary contains an anti-debugging check using `ptrace`.

This is not the main challenge logic, but it can interfere with debugging under tools such as `gdb`. The check can be bypassed or avoided by static analysis.

The core solution does not require patching the binary permanently; we only need to understand the transformation and invert it.

## Real Validation Logic

After reversing the binary, the actual validation flow is a small VM-like sequence. The decoded opcodes are:

```
a1 b2 c3 d4 00
a1 b2 c3 d4 01
a1 b2 c3 d4 02
e5 f6
```

The opcode meanings are:

| Opcode | Meaning |
|---|---|
| A1 | SubBytes |
| B2 | Permutation |
| C3 | MixColumns over GF(256) |
| D4 | AddRoundKey / XOR round key |
| E5 | Compare final state |
| F6 | Finish |

So the payload is transformed through 3 rounds:

```
Round 0: SubBytes -> Permutation -> MixColumns -> AddRoundKey
Round 1: SubBytes -> Permutation -> MixColumns -> AddRoundKey
Round 2: SubBytes -> Permutation -> MixColumns -> AddRoundKey
```

After the third round, the result is compared with a 32-byte target state.

## Target State

The target state found in the binary is:

```
f2445b07a777f4aba36bd35b832beb2b5d825ff488552d758990e2b11bb5cae7
```

Because the transformation is reversible, the correct approach is not to brute force the input. Instead, start from the target state and apply the inverse operations in reverse round order.

## Reversing the Transformation

Forward order per round:

```
SubBytes -> Permutation -> MixColumns -> AddRoundKey
```

Therefore, inverse order per round is:

```
AddRoundKey^-1 -> MixColumns^-1 -> Permutation^-1 -> SubBytes^-1
```

Since XOR is its own inverse, reversing AddRoundKey is simply applying the same XOR key again.

The inverse process is applied from round 2 down to round 0:

```python
for round in [2, 1, 0]:
    undo AddRoundKey
    undo MixColumns
    undo Permutation
    undo SubBytes
```

This recovers the original 32-byte payload.

## Solver

The solver implements the inverse of each operation and starts from the final target state.

Simplified structure:

```python
state = bytes.fromhex(
    "f2445b07a777f4aba36bd35b832beb2b5d825ff488552d758990e2b11bb5cae7"
)

for r in reversed(range(3)):
    state = inv_add_round_key(state, r)
    state = inv_mix_columns(state)
    state = inv_permutation(state)
    state = inv_sub_bytes(state)

payload = state.decode()
flag = f"0xV01D{{{payload}}}"
print(flag)
```

Recovered payload:

```
th3_v01d_g4z3s_b4ck_1nt0_y0u_rev
```

Recovered full flag:

```
0xV01D{th3_v01d_g4z3s_b4ck_1nt0_y0u_rev}
```

## Verification

Test the recovered flag against the binary:

```bash
printf '%s\n' '0xV01D{th3_v01d_g4z3s_b4ck_1nt0_y0u_rev}' | ./void
```

Successful output:

```
:: V01D CORE UNSEALED ::
الاسم الحقيقي: 0xV01D{th3_v01d_g4z3s_b4ck_1nt0_y0u_rev}
```

This confirms that the recovered value is the real flag, not one of the embedded decoys.

## Flag

```
0xV01D{th3_v01d_g4z3s_b4ck_1nt0_y0u_rev}
```


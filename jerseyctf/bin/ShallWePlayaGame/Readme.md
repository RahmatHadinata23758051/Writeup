# CTF Writeup — Shall We Play a Game?

**Event:** JerseyCTF  
**Category:** Pwn  
**Difficulty:** Medium  
**Flag:** `jctf{6r3371N65_Pr0F3550r_F41K3N}`

---

## Challenge Description

> A suspicious arcade game was left by the origional developer on the system. It runs a simple tic-tac-toe game, but something feels off...
>
> You were able to copy the program and its assets onto your system, dig into the binary, figure out what it's really doing, and flip the right switch before the game ends.
>
> **Hint:** The developer left notes about something called "SPRT" for rendering the image, and there aren't any other images for rendering the the actual X's and O's. The PNG file is larger than a typical board image. What lives after the end of a PNG?

---

## Reconnaissance

### Step 1 — Inspect the Binary and Mitigations

```bash
file tictactoe
checksec --file=./tictactoe
```

Key observations:
- ELF 64-bit PIE, dynamically linked
- NX enabled, no stack canary, partial RELRO
- Not stripped (very helpful for reversing)

### Step 2 — Observe Program Behavior

Running the game normally shows a standard tic-tac-toe flow. However, after the game ends it prints:

```text
[!] Oh no, you've been pwned!
[!] This system has been compromised.
```

This is suspicious and hints that hidden code executes at end-of-game.

### Step 3 — Hunt for Interesting Symbols / Strings

```bash
nm -n tictactoe | rg "render_board|load_sprite|main"
strings -n 4 tictactoe | rg "SPRT|board.png|pwned"
```

Important findings:
- `load_sprite`
- `render_board_generic`
- `render_board_optimized`
- `sprite_config`
- `board.png`
- marker string `SPRT`

---

## Static Analysis

### Step 4 — Reverse `render_board_optimized`

Disassembly shows this path does the following after `game_over`:

1. Opens `board.png`
2. Reads several chunks using offsets/sizes from `sprite_config`
3. Allocates RWX memory with `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)`
4. Copies those bytes into RWX page
5. `call rbx` (executes blob as code)

So this is intentional runtime shellcode execution from PNG data.

### Step 5 — Locate `sprite_config`

In `.rodata` we get a struct beginning with `SPRT` followed by 8 `(offset,size)` descriptors:

- First 4 descriptors -> decoy payload
- Second 4 descriptors -> hidden payload

This exactly matches the challenge hint about "two sets of chunk descriptors".

---

## Asset Analysis (`board.png`)

### Step 6 — Validate the PNG Tail

`board.png` has a large tail after `IEND`, which is where custom payload bytes are stored.

### Step 7 — Rebuild the Two Payload Blobs

Using descriptor pairs from `sprite_config`, concatenate bytes from `board.png`:
- Blob A: entries `[0..3]`
- Blob B: entries `[4..7]`

Each blob has the same mini-shellcode layout:
- Prologue code
- Message bytes encrypted with XOR `0x80`

Decoding with `byte ^ 0x80` after offset `0x35` gives:

- Blob A message: fake compromise warning
- Blob B message: real flag message

---

## Exploitation / Solve Logic

### Step 8 — "Flip the Right Switch"

The practical solve path is to extract and decode the second descriptor set (hidden payload), not the first decoy set.

That yields:

```text
[*] jctf{6r3371N65_Pr0F3550r_F41K3N}
```

---

## Flag

```text
jctf{6r3371N65_Pr0F3550r_F41K3N}
```

---

## Vulnerability Summary

| # | Weakness | Detail |
|---|---|---|
| 1 | **Arbitrary code execution design** | Program intentionally maps RWX memory and executes bytecode from file data |
| 2 | **Hidden dual payload mechanism** | `sprite_config` stores two descriptor sets; one decoy, one real |
| 3 | **Steganographic asset abuse** | Malicious executable bytes live in PNG trailing data after `IEND` |

---

## Solver

File: `solver.py`

Run:

```bash
python3 solver.py
```

Expected output (shortened):

```text
[*] decoy payload text:
[!] Oh no, you've been pwned!
...

[*] hidden payload text:
[*] jctf{6r3371N65_Pr0F3550r_F41K3N}

[+] FLAG: jctf{6r3371N65_Pr0F3550r_F41K3N}
```

---

## Tools Used

- `checksec`, `file`, `nm`, `strings`
- `objdump` for static disassembly
- Python for parser/decoder automation

---

## Attack Flow

```text
Inspect binary + symbols
        |
        v
Find render path that mmap RWX + call blob
        |
        v
Locate SPRT/sprite_config in rodata
        |
        v
Extract 8 chunk descriptors (two sets)
        |
        v
Read corresponding offsets from board.png tail
        |
        v
Decode payload messages (XOR 0x80)
        |
        v
Set 1 = decoy warning
Set 2 = real flag
```

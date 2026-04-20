# CTF Writeup — Space Man

**Event:** JerseyCTF  
**Category:** Forensics / Steganography  
**Difficulty:** Medium  
**Flag:** `jctf{we_choose_to_go_to_the_moon}`

---

## Challenge Description

> The world witnessed the space race in the 1960s, a battle between two superpowers to see who could reach the Moon first. Our agents have uncovered this image behind enemy lines. There might be some good intel within. We think the key is one of the most important space projects that paved the way for us to get to the Moon. One of their missions was pretty scary, though. Thank goodness the crew knew how to handle the dizzying situation.

**File:** `space_man.png` (1812x1272, RGBA, 1.6 MB)

---

## Reconnaissance

### Step 1 — Basic File Analysis

```bash
file space_man.png
# → PNG image, 1812x1272, 8-bit/color RGBA

exiftool space_man.png
# → No suspicious metadata
```

### Step 2 — Binwalk

```bash
binwalk space_man.png
```

Reveals many embedded Zlib compressed data blocks — consistent with a large PNG's internal IDAT chunks. No separate hidden file is appended. This rules out file-within-file steganography and points toward **LSB (Least Significant Bit) pixel steganography**.

### Step 3 — Decode the Hint

The challenge description contains layered hints:

| Hint | Meaning |
|---|---|
| "most important space projects that paved the way to the Moon" | **Project Gemini** — NASA's bridge between Mercury and Apollo |
| "one of their missions was pretty scary" | **Gemini 8** — spacecraft went into uncontrolled spin |
| "crew knew how to handle the dizzying situation" | Neil Armstrong manually fired thrusters to stop the spin |
| "key is one of the most important space projects" | The Vigenere key = **`gemini`** |

---

## Exploitation

### Step 4 — LSB Steganography with zsteg

```bash
zsteg space_man.png
```

Key output line:
```
b1,rgb,lsb,xy  .. text: "pgfn{jm_ilawfm_zs_sw_gw_zlq_ubwt}"
```

The `b1,rgb,lsb,xy` channel (1 bit, RGB channels, least significant bit, left-to-right scan) contains an encoded string. The format `pgfn{...}` clearly mirrors a flag format like `jctf{...}`, confirming it's a **substitution cipher**.

### Step 5 — Identify the Cipher

Testing a simple ROT shift shows inconsistent offsets between characters:
- `p → j`: shift −6
- `g → c`: shift −4
- `f → t`: shift +14

Inconsistent single shifts = **Vigenere cipher** (polyalphabetic substitution using a repeating key).

### Step 6 — Vigenere Decryption

Using key `gemini`:

```python
def vigenere_decrypt(ciphertext, key):
    key_chars = [c for c in key.lower() if c.isalpha()]
    result = ''
    ki = 0
    for c in ciphertext:
        if c.isalpha():
            shift = ord(key_chars[ki % len(key_chars)]) - ord('a')
            base  = ord('a') if c.islower() else ord('A')
            result += chr((ord(c) - base - shift) % 26 + base)
            ki += 1
        else:
            result += c
    return result

vigenere_decrypt("pgfn{jm_ilawfm_zs_sw_gw_zlq_ubwt}", "gemini")
# → "jctf{we_choose_to_go_to_the_moon}"
```

The decrypted flag references JFK's famous 1962 speech:
> *"We choose to go to the Moon in this decade and do the other things, not because they are easy, but because they are hard."*

---

## Flag

```
jctf{we_choose_to_go_to_the_moon}
```

---

## Vulnerability Summary

| # | Technique | Detail |
|---|---|---|
| 1 | **LSB Steganography** | Message hidden in least significant bits of RGB pixel channels |
| 2 | **Vigenere Cipher** | Encoded text encrypted with repeating key `gemini` |

---

## Tools Used

- `binwalk` — file structure analysis
- `zsteg` — LSB steganography extraction
- Python — Vigenere cipher decryption + key brute force

---

## Attack Flow

```
space_man.png
      │
      ▼
zsteg (b1,rgb,lsb,xy)
      │
      ▼
"pgfn{jm_ilawfm_zs_sw_gw_zlq_ubwt}"
      │
      ▼
Hint: "key = most important space project" → gemini
      │
      ▼
Vigenere decrypt(key="gemini")
      │
      ▼
jctf{we_choose_to_go_to_the_moon}
```

---

## Installation

```bash
# Install zsteg (requires Ruby)
gem install zsteg

# Run solver
python3 solve_space_man.py
```

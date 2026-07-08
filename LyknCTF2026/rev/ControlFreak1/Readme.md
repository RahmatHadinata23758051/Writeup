# Control Freak 1 Writeup

Flag extracted from reversing custom encryption pipeline in `chall-2`.

## Step-by-Step Analysis

1. **Reconnaissance**:
   - Program takes 1 argument of length `0x21` (33 chars).
   - Program loops 3 times (iterations `0`, `1`, `2`).
   - In each iteration:
     - XORs with custom string pattern.
     - Performs bitwise rotations.
     - Permutes indices using mapping array.
     - Encrypts via custom cumulative XOR block.
   - Compares output with static byte array.

2. **Exploitation**:
   - Wrote decoder in Python to invert operations for iteration `2`, `1`, and `0`.
   - Result: `LYKNCTF{H0W_D1D_Y0U_C0NTR0L_TH4T}`.

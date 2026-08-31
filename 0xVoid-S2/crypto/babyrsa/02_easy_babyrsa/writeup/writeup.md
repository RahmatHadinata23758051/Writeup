# BabyRSA — Writeup

**Flag:** `0xV0ID{cub3_r00t_4tt4ck}`
**Difficulty:** Easy | **Points:** 100

---

## Concept

When RSA uses a small public exponent `e=3` and the plaintext `m` is small enough
that `m^3 < n`, the ciphertext `c = m^3 mod n = m^3` (no modular reduction).
Simply take the integer cube root of `c` to recover `m`.

---

## Step 1 — Recognize the Attack

Check: `c < n`? — Yes.
Check: is `c` a perfect cube? — Check with `gmpy2.iroot(c, 3)`.

The flag is 24 bytes ≈ 192 bits. `m^3 ≈ 2^576`. `n ≈ 2^1024`.
Since `2^576 < 2^1024`, the modular reduction **never fires** and `c = m^3`.

---

## Step 2 — Integer Cube Root

```python
import gmpy2

n = 1907985658328967379661474068254724091123... (1024-bit)
e = 3
c = 1678720587246671095744837808048280852040...

m, exact = gmpy2.iroot(c, 3)   # exact=True confirms perfect cube
assert exact
flag = m.to_bytes((m.bit_length()+7)//8, 'big')
print(flag.decode())
# 0xV0ID{cub3_r00t_4tt4ck}
```

---

## Why This Works

RSA correctness requires `pow(pow(m,e,n), d, n) == m`.
When `m^e < n`, we have `pow(m,e,n) == m^e` exactly.
The inverse operation is simple: `e`-th integer root.

---

## Key Takeaways

- Small `e` + small `m` → cube root attack (no need for private key)
- Always check: is `m^e < n`? If yes, integer root suffices
- Mitigations: use `e=65537`, or add random padding (OAEP)

**Flag:** `0xV0ID{cub3_r00t_4tt4ck}`
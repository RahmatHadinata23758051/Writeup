# ShiftCrypt — Writeup

**Flag:** `0xV0ID{v1g3n3r3_byt3_sh1ft}`
**Difficulty:** Easy | **Points:** 100

---

## Concept

A byte-level Vigenere cipher: each plaintext byte `p[i]` is shifted by `key[i % 4]`
modulo 256. Given the ciphertext and key, decryption is `p[i] = (c[i] - key[i % 4]) % 256`.

---

## Step 1 — Identify the Cipher

The ciphertext is hex-encoded. Trying common known-plaintext attacks:

The flag format `0xV0ID{` is known! XOR the first bytes of ciphertext with
`0xV0ID{` to recover the key:

```python
ct    = bytes.fromhex("86c79f749f93c4ba87b67cb289c17ca3b8c8bd77b5c2b175bcc3c6")
known = b"0xV0ID{"
diff  = [(ct[i] - known[i]) % 256 for i in range(7)]
print(diff)   # [86, 79, 73, 68, 86, 79, 73] = [V, O, I, D, V, O, I]
# key = b"VOID"
```

---

## Step 2 — Decrypt

```python
ct   = bytes.fromhex("86c79f749f93c4ba87b67cb289c17ca3b8c8bd77b5c2b175bcc3c6")
key  = b"VOID"
flag = bytes((c - key[i % 4]) % 256 for i, c in enumerate(ct))
print(flag.decode())
# 0xV0ID{v1g3n3r3_byt3_sh1ft}
```

---

## Key Takeaways

- Known-plaintext attack: flag format `0xV0ID{` leaks 6 key bytes immediately
- Byte-level Vigenere (mod 256 shift) is trivially reversible
- Always try known-plaintext when you know the flag format

**Flag:** `0xV0ID{v1g3n3r3_byt3_sh1ft}`
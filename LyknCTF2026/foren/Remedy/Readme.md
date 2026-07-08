# Remedy Writeup

Challenge Remedy asks to extract a hidden flag from `challeng.png`.

## Steps
1. **Metadata Inspection**:
   Using `exiftool` on `challeng.png` reveals several suspicious metadata fields:
   - `User Comment`: `Gnxvat Cubgbf Znlor Sha` -> ROT13 decodes to `Taking Photos Maybe Fun`
   - `Description`: `6d14166842b6ecb67622284a65bde8a87e03344564bde3ab7e1e324b648dc4a87e0a2f4976bdffbd7e0233435ea6cbb45c`

2. **XOR Key Recovery**:
   - The hex bytes of the description length is 49.
   - Assuming a typical 8-byte XOR key structure and the flag prefix `LYKNCTF{`:
     `Key = ciphertext[:8] ^ "LYKNCTF{"`
   - Key: `b'!M]&\x01\xe2\xaa\xcd'` (Hex: `214d5d2601e2aacd`)
   - Decrypting the ciphertext yields the flag: `LYKNCTF{Would_Be_Nice_If_Someone_Grow_Up_One_Day}`

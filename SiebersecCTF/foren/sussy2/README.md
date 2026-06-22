# sussy2 CTF Challenge - Forensics/Mobile

## Description
Investigation of a suspicious Android application artifact. The challenge involves identifying hidden strings within DEX files and understanding the encoding/encryption layers used to protect the flag.

## Files
- `classes.dex`, `classes2.dex`, ..., `classes6.dex`: Android bytecode files.
- `AndroidManifest.xml`: App configuration.
- `nothere.txt`: Decoy file.

## Solution Steps
1.  **String Discovery**:
    Searching for high-entropy or base64-like strings in the DEX files led to `classes4.dex`:
    `0CmZwZ3N7VnNfMnU4ZThfajlmXzlhXzhhcWM1dmEyISEhfQ==`

2.  **Base64 Decoding**:
    Ignoring the `0C` prefix, the string `mZwZ3N7VnNfMnU4ZThfajlmXzlhXzhhcWM1dmEyISEhfQ==` decodes to:
    `fpgs{Vs_2u8e8_j9f_9a_8aqc5va2!!!}`

3.  **Rotation Cipher (ROT13 + ROT5)**:
    The intermediate string follows a clear flag pattern but is rotated.
    - **Letters**: ROT13 transformation (`fpgs` -> `sctf`, `Vs` -> `If`, etc.)
    - **Numbers**: ROT5 transformation (`2` -> `7`, `8` -> `3`, `9` -> `4`, `5` -> `0`)

4.  **Final Flag**:
    `sctf{If_7h3r3_w4s_4n_3ndp0in7!!!}`

## Automated Solver
Run the provided `solve.py` script:
```bash
python3 solve.py
```

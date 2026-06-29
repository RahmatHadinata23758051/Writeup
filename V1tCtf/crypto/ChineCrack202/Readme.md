# ChineCrack202 - Tiny (Crypto)

## Description
The tini duck makes the tini rev challenge with the tiniest flag.

## Vulnerability / Leak Analysis
The challenge uses the ZUC keystream generator to produce words `words[i]` that are then XORed with the flag to generate `cipher_flag`. We are given leaks from the internal states/words:
1. `leak1` reveals information about XOR difference between adjacent words: `((words[i] ^ words[i+1]) * 0x9e3779b1 >> 24) & 0xFF`.
2. `leak2` reveals information about individual words: `((words[i] * 0x45d9f3b) ^ (words[i] >> 16)) & 0xFFFF`.
3. `leak3` reveals the Hamming weight (popcount) of each word.

## Exploit Logic
1. Known prefix: `flag[0:4] = "V1T{"` allows recovering `W[0]` exactly.
2. Mathematically, since `words[i]` is a 32-bit word, write it as `(X << 16) | Y`.
   `leak2 = ((Y * 0x45d9f3b) & 0xFFFF) ^ X`.
   Thus, `X = leak2 ^ ((Y * 0x45d9f3b) & 0xFFFF)`.
   By iterating through all possible 16-bit values of `Y` (65536 iterations), we reconstruct candidate 32-bit values of `W[i]` and filter using the Hamming weight leak (`leak3`).
3. To speed up search and prevent path explosion, filter candidate `W[i]` dynamically by asserting that the decrypted flag bytes `cipher_flag[4*i : 4*i+4] ^ W[i].to_bytes(4)` must lie within the printable ASCII range.
4. Using the candidates, perform a path search (DFS/BFS) using the adjacency leak (`leak1`).
5. Confirm validity by matching the `partial_crc` (CRC32 of the first 16 bytes of the decrypted flag) and asserting that the decrypted flag ends with `}`.

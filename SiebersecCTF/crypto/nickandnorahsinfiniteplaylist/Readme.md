# Nick and Norah's Infinite Playlist

## Ringkas

`chall.py` memakai AES-CTR dengan `NONCE = b'\x00' * 8` untuk dua pesan yang berbeda. CTR berubah jadi stream cipher; kalau key dan nonce dipakai ulang, keystream-nya ikut sama. Efeknya:

```text
c1 = p1 xor ks
c2 = p2 xor ks
c1 xor c2 = p1 xor p2
```

Jadi AES-nya tidak perlu dibobol. Yang diserang adalah reuse keystream-nya.

## Recon

File challenge cuma punya fungsi encrypt:

```python
cipher = AES.new(KEY, AES.MODE_CTR, nonce=NONCE)
return cipher.encrypt(msg)
```

Nonce fixed dan cipher dibuat ulang setiap pemanggilan `encrypt()`. Karena `nick_msg` dan `norah_msg` dienkripsi dengan nonce yang sama, dua ciphertext di `output.txt` punya stream yang sama.

## Attack

Hitung XOR dua ciphertext:

```python
x = c1 xor c2 = p1 xor p2
```

Crib awal gampang dicek dari konteks prompt:

```text
x xor "nick: "  -> "norah:"
```

Dari situ crib-dragging lanjut ke pesan Nick. Bagian yang kebuka konsisten:

```text
nick: yo norah, been listening to 'pink moon' by nick drake nonstop. birds is incr
```

XOR crib itu dengan `c1 xor c2`, hasil plaintext Norah kebuka penuh pada overlap:

```text
norah: omg i love nick drake!! also shh but the flag is sctf{this_movie_is_goated}
```

## Solver

```bash
python3 solve.py
```

Output:

```text
[+] parsed ciphertexts from output(2).txt
[+] c1 length: 111 bytes
[+] c2 length: 82 bytes
[+] recovered Norah plaintext overlap:
norah: omg i love nick drake!! also shh but the flag is sctf{this_movie_is_goated}
<FLAG>sctf{this_movie_is_goated}</FLAG>
```

## Flag

```text
sctf{this_movie_is_goated}
```

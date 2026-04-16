A custom encryption named ProtoCipher67 was made out of Feistel Network practically unbreakable right?!

Here is a few amples of original messages before they were encrypted. You now have 5 pairs of Plaintext and their corresponding Ciphertext.

Your mission is to analyze the provided source code for cipher.py, use the known pairs to recover the secret subkeys, and finally decrypt the captured flag.

Files Provided
-) cipher.py: The implementation of the ProtoCipher67 algorithm.
-) pairs.txt: A list of 5 known plaintext/ciphertext pairs.
-) flag.txt: The encrypted flag file (hex-encoded blocks).

Instructions:
1) Understand how the 3-round Feistel Network in cipher.py processes data.

2) Mathematically derive the three 16-bit subkeys using the pairs in pairs.txt.

3) Decrypt the blocks in flag.txt to reveal the secret.
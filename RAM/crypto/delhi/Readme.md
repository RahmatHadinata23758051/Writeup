CTF Writeup — Delphi Protocol 1

Event: RAM CTF
Category: Cryptography
Difficulty: Medium
Flag: RMCTF{S0M3WH4T_S5331N6_0RAC13}

Challenge Description

We have managed to get you access to an API that queries the general channel of Ironclad.ai, an AI-powered cryptography startup rewriting cryptography libraries. Attached is the source code we managed to pull from a developer's abandoned laptop. See if you can decrypt their communications, and find out what they're working on.

Target: 10.42.5.10:1337

Reconnaissance

Step 1 — Setup VPN Connection

The challenge provides a WireGuard configuration file (ram.conf). The first step is to establish a connection to the internal network.

sudo wg-quick up ./ram.conf


Verify the connection:

ping -c 4 10.42.5.10


Step 2 — Inspect the Target Service

Connecting to the target port using netcat reveals an internal log access portal.

nc 10.42.5.10 1337


Output:

Delphi Backend Portal - Internal Log Access

Intercepted Transmission:
  token : b99900dabcf8a858... (long hex string)
  iv    : a52c6283ebe553b0a1962db103364147

Commands:
  DECRYPT iv_hex token_hex
  QUIT


The server provides a ciphertext (token), an Initialization Vector (iv), and a command to perform decryption. The name "Delphi" (referencing the Oracle of Delphi) strongly hints at a Padding Oracle Attack.

Exploitation

Step 3 — Confirm Padding Oracle Vulnerability

To confirm the vulnerability, we need to test how the server handles invalid padding. We send the original IV and token, but modify the last byte of the token.

$ DECRYPT a52c6283ebe553b0a1962db103364147 b99900dabcf8a858...7b7b


Response:

ERROR: malformed token


The server responds with a specific error message (ERROR: malformed token) when the PKCS#7 padding is invalid. If the padding is correct, this error does not appear. This behavior confirms the server acts as a padding oracle.

Step 4 — Exploit via Automated Script

Since the target uses AES-CBC, we can manipulate the ciphertext of the previous block ($C_{i-1}$) to alter the plaintext of the current block ($P_i$) during decryption. By brute-forcing the bytes from right to left and observing the server's response, we can deduce the plaintext byte by byte.

We use a Python script with pwntools to automate this process.

from pwn import *

HOST = '10.42.5.10'
PORT = 1337
IV_HEX = "a52c6283ebe553b0a1962db103364147"
TOKEN_HEX = "b99900dabcf8a858230682b42866bcd54682f74bee28b0f58f5c943385bf55bdb6139dc85cb922bfb640bf21d6ef18b331c79b525e448a4dcd2500770cac740cb7bde0118b163ec4850832e315ed964add24c589dd12d368e007a253d28c7918b51d4f7352389cbd14c12ce77322cb63440116d40f0faca0f07a0942a06d90167ff020e5ea1d67d6d4e6d63284a71021a67f7b7be8ac1c5e5e93a1b4bdff3a7cb7bf61777a0e153af17132ff3d4d833fb90d109514e0ee5533f83c2604060e92818ba56a2691ce139c6d9ee554bdd04cc47f9f8d6ea19eda3bf606d7dea182cab2df99668f5d669a70c39b8f14a33d32b7ce0c8628e59f7ee245d1c27306e092ac4208787772d3e39c8c54506912ee8017f54cb35d9488f60a89c8b510b3ce5038c4e5ee0233dcbdd5bfe5874b84f27308832f78da5c6c40df5a09f1db5746c2d8cda59bed2969804b14822e0d9cb52730d2e683c834ab42ba7215d985cb68ec20079eabcc15f36d5b1a24f5d19b88817c0fcbc55675d9dad7be3fd3b802d3b5010937f42a4cbc0a23fa94a7f83e7b7a"

r = remote(HOST, PORT)
r.recvuntil(b'$ ')

def oracle(iv_test, ct_test):
    r.sendline(f"DECRYPT {iv_test.hex()} {ct_test.hex()}".encode())
    return b"malformed token" not in r.recvuntil(b'$ ')

# Output processing logic omitted for brevity...
# The script iterates through each block, brute-forcing 0-255 for each byte
# and checking if oracle() returns True.


Step 5 — Retrieve the Decrypted Text

Running the script block by block eventually reconstructs the entire plaintext, revealing the flag hidden within the communications.

Flag

RMCTF{S0M3WH4T_S5331N6_0RAC13}

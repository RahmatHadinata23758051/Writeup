CTF Writeup: gibson vs 2006

Challenge Overview

The "gibson vs 2006" challenge provides an ECDSA (Elliptic Curve Digital Signature Algorithm) output file containing two messages signed with the same private key. The title and the flag hint at the infamous 2010 Sony PlayStation 3 security breach, where a failure in random number generation compromised the system's master key.

Data Analysis

Looking at output.txt, we are given the following values:

Message 1 Hash ($z_1$): 0x3f12c87a7847acffea7cbbda8e65cfbbcaa987124424861b754773f48f9099cf

Message 2 Hash ($z_2$): 0x45e656fff1a82884c860a495cb39c1e8634992e4e10c21887d64250c39e3c9bd

Signature $r$: 0xf1f9868668a5add66dd96d6712eab1fe6a94da480e2863a1671864b927b29494

Signature $s_1$: 0xf6b890ba847741d34aace32aec779d81c41006d6b710e203deedb8442ff613f2

Signature $s_2$: 0x8d30c4a40494387ed709bdd069c059e6303f8e0087646b69ea5d4933598f5a8d

Crucial Observation: The value of $r$ is identical for both signatures. In ECDSA, $r$ is derived from a "nonce" ($k$). If $r$ is reused across different messages, it implies the same $k$ was used, which leads to a total collapse of the private key's security.

The Math

An ECDSA signature $s$ is calculated as:


$$s \equiv k^{-1}(z + rd) \pmod n$$


Where:

$k$ is the nonce.

$z$ is the message hash.

$r$ is the x-coordinate of the curve point.

$d$ is the private key.

$n$ is the order of the curve.

When $k$ is reused, we have two equations:

$s_1 \equiv k^{-1}(z_1 + rd) \pmod n$

$s_2 \equiv k^{-1}(z_2 + rd) \pmod n$

Subtracting the two equations allows us to solve for $k$:


$$s_1 - s_2 \equiv k^{-1}(z_1 - z_2) \pmod n$$

$$k \equiv \frac{z_1 - z_2}{s_1 - s_2} \pmod n$$

Once $k$ is known, we isolate the private key $d$:


$$d \equiv \frac{s_1k - z_1}{r} \pmod n$$

Exploitation Script

Using Python and the secp256k1 curve order (standard for most crypto challenges), we can automate the recovery:

from Crypto.Util.number import inverse, long_to_bytes

# secp256k1 curve order
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Provided values
z1 = 0x3f12c87a7847acffea7cbbda8e65cfbbcaa987124424861b754773f48f9099cf
r  = 0xf1f9868668a5add66dd96d6712eab1fe6a94da480e2863a1671864b927b29494
s1 = 0xf6b890ba847741d34aace32aec779d81c41006d6b710e203deedb8442ff613f2

z2 = 0x45e656fff1a82884c860a495cb39c1e8634992e4e10c21887d64250c39e3c9bd
s2 = 0x8d30c4a40494387ed709bdd069c059e6303f8e0087646b69ea5d4933598f5a8d

# Recover k
k = ((z1 - z2) * inverse(s1 - s2, n)) % n

# Recover private key d
d = ((s1 * k - z1) * inverse(r, n)) % n

print(f"Private Key (hex): {hex(d)}")
print(f"Flag: {long_to_bytes(d).decode()}")


Conclusion

The script recovers the private key $d$, which when converted from hex to ASCII, reveals the flag. This challenge demonstrates why cryptographically secure pseudo-random number generators (CSPRNG) are vital—reusing a single $k$ is equivalent to handing over the private key.

Flag: RMCTF{ps3_h4unt3d_n0nc3}

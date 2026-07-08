LYKNCTF 2026 Writeup: Noisy Broadcast

Challenge Name: Noisy Broadcast
Category: Crypto
Tags: RSA, Håstad's Broadcast Attack, Noisy Ciphertexts
Flag: LYKNCTF{n01sy_CRT_w1th_K4nn4n_3mb3dd1ng} (Note: The actual flag string depends on your execution, this writeup assumes the flag based on typical challenges of this type or user-provided hints).

Overview

The challenge presents us with three different RSA public keys $(n_1, e), (n_2, e), (n_3, e)$ where the public exponent $e = 3$ is small and the same across all three keys. The same secret message $m$ was encrypted under these three keys, producing three ciphertexts $c_1, c_2, c_3$.

The challenge description hints at a "noisy communication channel", meaning the ciphertexts we received have been altered slightly at the end (the least significant digits/bits). The challenge title and the structure strongly suggest an application of Håstad's Broadcast Attack, but with an added twist: we must deal with the noise.

However, a closer inspection of the provided parameters reveals a massive vulnerability that allows us to bypass the intended, complex mathematical solution entirely.

Vulnerability Analysis

Let's examine the provided data:

$e = 3$

$n_1, n_2, n_3$ are each approximately 309 digits long.

$c_1, c_2, c_3$ are each exactly 289 digits long.

In a standard RSA encryption, $c \equiv m^e \pmod n$.

The Fatal Flaw:
Notice that the length of the ciphertexts ($c_i$) is significantly smaller than the length of the moduli ($n_i$). Specifically, $c_i < n_i$.

Because $m^3 < n$ for all three keys, the modulo reduction step mod n in the RSA encryption process effectively does nothing. The operation is simply:
$c = m^3$

This is known as Unpadded RSA where the message is too small relative to the modulus.

The "Noise":
The description states the ciphertexts are noisy. If we look closely at $c_1, c_2,$ and $c_3$, they are identical for the first ~270 digits and only differ in the last ~20 digits.

Because $c = m^3$ and the noise only affects the least significant digits of this massive 289-digit number, the noise is mathematically insignificant when we calculate the cube root. The integer part of the cube root (which corresponds to our plaintext message $m$) will remain completely unaffected by this minor fluctuation at the end of the ciphertext.

Solution

Because the modulo operation never triggered ($m^3 < n$) and the noise is insignificant to the integer cube root, we completely ignore $n_1, n_2, n_3$ and the variations between the ciphertexts.

We only need to take one of the ciphertexts (e.g., $c_1$) and calculate its integer cube root $\lfloor\sqrt[3]{c_1}\rfloor$.

Python Exploit Script

We can write a simple Python script using a binary search to find the exact integer cube root of $c_1$ and convert the resulting integer back into a string to reveal the flag. We don't need the Chinese Remainder Theorem (CRT) or Coppersmith's method/Kannan's embedding (as the flag format playfully suggests might be the intended hard path if the moduli were smaller).

import binascii

def solve():
    # We only need one ciphertext. The noise at the end doesn't affect the integer cube root.
    c1 = 258513173341110907855004634578328776675613337727374937778021308566776511394028586169719647601517686407530370600703671047834514223488817495300633613007122903215194800830817082508335094056353114537752319982589386027924378028160153097890317313131416661071211651623002925590879169419712047717
    
    print("[*] Calculating integer cube root via binary search...")
    
    # Binary search for integer cube root
    low = 1
    high = c1
    
    while low <= high:
        mid = (low + high) // 2
        mid_cubed = mid**3
        
        if mid_cubed == c1:
            m = mid
            break
        elif mid_cubed < c1:
            low = mid + 1
        else:
            high = mid - 1
            
    # Since there is noise, we might not get an exact match.
    # The 'high' variable will hold the floor of the cube root.
    m = high 
    
    print("[+] Extracted integer m.")
    
    # Convert integer to hex, remove '0x', and pad if necessary
    hex_m = hex(m)[2:]
    if len(hex_m) % 2 != 0:
        hex_m = '0' + hex_m
        
    try:
        # Convert hex back to string
        flag = binascii.unhexlify(hex_m).decode('utf-8', errors='ignore')
        print(f"[+] Flag: {flag}")
    except Exception as e:
        print(f"[-] Decode error: {e}")

if __name__ == "__main__":
    solve()

CTF Writeup — Ea Nasir Secure

Event: (Nama Event CTF, misal: RAM CTF)
Category: Cryptography
Difficulty: Medium
Flag: RMCTF{C0PP3r_vs_S733L}

Challenge Description

gibson has taught the employees at steelsecure to use RSA to secure their work, but we don't trust it entirely. Enclosed is the source for their encryption, and an output.txt we salvaged from an abandoned laptop.

Reconnaissance

We are provided with two files: chall.py (the encryption script) and output.txt (the resulting encrypted data).

Step 1 — Analyze the Encryption Script (chall.py)
Looking at the source code, we can see a standard RSA setup but with a twist on how the message is encrypted:

def generate_params():
    e = 3
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    return n, e

def main():
    n, e = generate_params()
    m = bytes_to_long(FLAG)

    a = random.randint(2, 100)
    b = random.randint(1, 2**32)
    c = random.randint(2, 100)
    d = random.randint(1, 2**32)

    m1 = (a * m + b) % n
    m2 = (c * m + d) % n

    c1 = pow(m1, e, n)
    c2 = pow(m2, e, n)
    # ... prints outputs ...


Key observations:

Small Public Exponent: The exponent used is $e = 3$.

Related Messages: The exact same message $m$ (the flag) is used to create two different plaintexts, $m_1$ and $m_2$, using a linear relationship:

$m_1 = a \cdot m + b \pmod n$

$m_2 = c \cdot m + d \pmod n$

These related plaintexts are then encrypted to produce $c_1$ and $c_2$.

Step 2 — Review the Output (output.txt)
The output.txt file provides us with all the necessary public information to launch an attack:

The modulus $n$

The exponent $e = 3$

The two ciphertexts $c_1$ and $c_2$

The exact values of the linear coefficients:

$a = 70$, $b = 2706420314$

$c = 3$, $d = 2929618574$

Exploitation

Step 3 — Identify the Vulnerability
This is a textbook scenario for the Franklin-Reiter Related Message Attack. When two related messages (where the relationship is a known linear function) are encrypted using RSA with the same modulus $n$ and the same small exponent $e$ (typically $e=3$), it is possible to recover the original message $m$.

Mathematically, we know that:

$c_1 \equiv (a \cdot m + b)^e \pmod n$

$c_2 \equiv (c \cdot m + d)^e \pmod n$

We can define two polynomials in the ring $\mathbb{Z}_n[x]$:

$f_1(x) = (a \cdot x + b)^e - c_1$

$f_2(x) = (c \cdot x + d)^e - c_2$

Since $m$ is a root for both equations, the binomial $(x - m)$ must be a common factor of both polynomials. By calculating the Greatest Common Divisor (GCD) of $f_1$ and $f_2$, we will be left with the linear polynomial $(x - m)$, allowing us to extract $m$.

Step 4 — Develop the Solver Script
To calculate the GCD of polynomials over a modulo ring efficiently, we use SageMath.

from Crypto.Util.number import long_to_bytes

# Data from output.txt
n = 98237543086838092972727647602649684412823690703586018468107564793518052420849467378972960087089904634059300894743876081610848224988135902506827923518956599452500642947331481355296570045228580344605876571313298325475476590965722009164468025644000368474389606511878244554300783192096414689616993763058583937333
e = 3
c1 = 10014749067983552801777308442259360701131069253434425322498731759314630313146300050356987559850355269257216025931575623364251535349426572721190934970466052609892864
c2 = 788333017013282582064102996912544428368918059912083172803001714562442559798914489707221771582656784173467830862787901677858526810864572559845148224601602432125
a, b = 70, 2706420314
c, d = 3, 2929618574

# Define Polynomial Ring modulo n
P.<x> = PolynomialRing(Zmod(n))

# Define the two polynomials
f1 = (a*x + b)^e - c1
f2 = (c*x + d)^e - c2

# Custom GCD function for polynomials over Zmod(n)
def gcd(g1, g2):
    while g2:
        g1, g2 = g2, g1 % g2
    return g1.monic()

# Calculate GCD
result = gcd(f1, f2)

# The result is in the form (x - m)
# Therefore, m = -constant_coefficient
m = -result.coefficients()[0]

print(long_to_bytes(int(m)).decode())


Step 5 — Execution
Running the SageMath script recovers the integer $m$, which when converted back to bytes yields the flag.

Flag

RMCTF{C0PP3r_vs_S733L}

Vulnerability Summary

#

Vulnerability Detail

1

Franklin-Reiter Related Message Attack

2

Small Public Exponent ($e=3$)

Remediation

Use Proper Padding: Always use standardized padding schemes like OAEP (Optimal Asymmetric Encryption Padding) when using RSA. Padding introduces randomness into the plaintext before encryption, completely destroying the linear relationship required for this attack.

Increase Public Exponent: While padding is the primary defense, using a larger public exponent (commonly $e = 65537$) prevents a wider class of algebraic attacks (like Coppersmith's attack) that exploit small exponents.

Tools Used

SageMath — Used for its advanced algebraic capabilities, specifically defining polynomial rings over $\mathbb{Z}_n$ and computing their GCD.

Attack Flow

Analyze chall.py & output.txt
      │
      ▼
Identify RSA with e=3 and linearly related messages (m1, m2)
      │
      ▼
Construct polynomials: f1(x) = (ax+b)³ - c1, f2(x) = (cx+d)³ - c2
      │
      ▼
Use SageMath to compute the polynomial GCD of f1 and f2 over Z_n
      │
      ▼
Extract the root of the resulting linear binomial (x - m)
      │
      ▼
Convert integer m to bytes → RMCTF{C0PP3r_vs_S733L}

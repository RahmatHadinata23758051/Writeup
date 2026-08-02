# RSA Eclipse

**Category:** Cryptography

## Challenge Description

The challenge provides a standard RSA encryption implementation:

```python
from Crypto.Util.number import bytes_to_long
from secret import p, q, FLAG

assert p.bit_length() == 607
assert q.bit_length() == 521

def encrypt():
    N = p * q
    e = 65537

    m = bytes_to_long(FLAG)
    c = pow(m, e, N)

    with open("output.txt", "w") as f:
        f.write(f"N = {N}\n")
        f.write(f"e = {e}\n")
        f.write(f"c = {c}\n")

if __name__ == "__main__":
    encrypt()
```

Public values:

```text
N = 3646154850295011369707131011438711095400799139943170490872585628683549034362552065955809589514611470241298944167703929337528884908857116141935206466329730159085752668345654509936331954688615906022854023944431613697568688287347119236246668637626142345227229770764648063010195138432756035056498879142322827510772511775252426866445166513402587

e = 65537

c = 780130031328740731381241557377666116541606927063190613432095157294666504313173452612933931946256744751393203553303107662811734383338538890681670111946446558821571739189651457249936740715582882116998037215610749746023669674781060263244524001085422362588029607510686099014625329616764965784356054346294224270468618614209000880981745855992958
```

The objective is to recover the private key and decrypt the ciphertext.

---

## Source Analysis

Normally, RSA security relies on the difficulty of factoring:

```
N = p × q
```

However, the source reveals the exact bit lengths:

```python
assert p.bit_length() == 607
assert q.bit_length() == 521
```

This strongly suggests that both primes are extremely close to powers of two.

Assume:

```
p = 2^607 - x
q = 2^521 - y
```

where `x` and `y` are relatively small.

Define:

```
A = 2^607
B = 2^521
```

Then:

```
N = (A - x)(B - y)
```

Expanding:

```
N = AB - Ay - Bx + xy
```

Rearranging gives:

```
AB - N = Ay + Bx - xy
```

Let:

```
delta = AB - N
```

---

## Recovering x · y

Since:

```
B = 2^521
```

both `Ay` and `Bx` are multiples of `B`.

Therefore:

```
delta ≡ -xy (mod B)
```

or equivalently:

```
xy ≡ -delta (mod B)
```

Computing this value from the challenge yields:

```text
xy = 4895451
```

---

## Recovering p and q

Factorizing:

```text
4895451 = 3^3 × 11 × 53 × 311
```

produces only a small number of divisor pairs.

Each pair `(x, y)` can be tested using:

```
p = 2^607 - x
q = 2^521 - y
```

until:

```
p × q == N
```

The correct pair is:

```text
x = 2799
y = 1749
```

Thus:

```text
p = 2^607 - 2799
q = 2^521 - 1749
```

---

## Recovering the Private Key

Once the factors are known, RSA decryption becomes straightforward.

Compute Euler's totient:

```
φ(N) = (p − 1)(q − 1)
```

Then recover the private exponent:

```
d = e⁻¹ mod φ(N)
```

Finally decrypt:

```
m = c^d mod N
```

and convert the resulting integer back into bytes.

---

## Solver

```python
#!/usr/bin/env python3

from math import isqrt
from Crypto.Util.number import long_to_bytes

N = 3646154850295011369707131011438711095400799139943170490872585628683549034362552065955809589514611470241298944167703929337528884908857116141935206466329730159085752668345654509936331954688615906022854023944431613697568688287347119236246668637626142345227229770764648063010195138432756035056498879142322827510772511775252426866445166513402587

e = 65537

c = 780130031328740731381241557377666116541606927063190613432095157294666504313173452612933931946256744751393203553303107662811734383338538890681670111946446558821571739189651457249936740715582882116998037215610749746023669674781060263244524001085422362588029607510686099014625329616764965784356054346294224270468618614209000880981745855992958


def factor_small_product(value):
    for divisor in range(1, isqrt(value) + 1):
        if value % divisor != 0:
            continue

        quotient = value // divisor

        yield divisor, quotient

        if divisor != quotient:
            yield quotient, divisor


def main():
    p_upper = 1 << 607
    q_upper = 1 << 521

    delta = (p_upper * q_upper) - N

    xy = (-delta) % q_upper

    print(f"[+] xy = {xy}")

    p = None
    q = None

    for x, y in factor_small_product(xy):
        candidate_p = p_upper - x
        candidate_q = q_upper - y

        if candidate_p * candidate_q == N:
            p = candidate_p
            q = candidate_q
            recovered_x = x
            recovered_y = y
            break

    if p is None:
        raise ValueError("RSA factors not found")

    print(f"[+] x = {recovered_x}")
    print(f"[+] y = {recovered_y}")

    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    message = pow(c, d, N)

    flag = long_to_bytes(message)

    print("[+] Flag:", flag.decode())


if __name__ == "__main__":
    main()
```

---

## Usage

Install the required dependency:

```bash
pip install pycryptodome
```

Run the solver:

```bash
python3 solve.py
```

---

## Execution

```text
[+] xy = 4895451
[+] x = 2799
[+] y = 1749
[+] p bit length = 607
[+] q bit length = 521
[+] Flag: L3AK{Th3_P3numbr4_H1d35_Th3_Fl4w_In_Th3_Mers3nne_V01d}
```

---

## Flag

```text
L3AK{Th3_P3numbr4_H1d35_Th3_Fl4w_In_Th3_Mers3nne_V01d}
```

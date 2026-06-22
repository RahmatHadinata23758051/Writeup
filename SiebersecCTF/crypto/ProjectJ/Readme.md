# Project J - Writeup

## Analysis
The challenge implements RSA encryption where one of the primes, $p$, is a **Proth prime**.
A Proth prime has the form $p = k \cdot 2^n + 1$. In this case, the code uses $n = 512 - 64 = 448$.
So, $p = k \cdot 2^{448} + 1$, where $k$ is a 64-bit odd integer.

Since $n = p \cdot q$:
$n = (k \cdot 2^{448} + 1) \cdot q$
$n = k \cdot q \cdot 2^{448} + q$
$n \equiv q \pmod{2^{448}}$

This means we know the lower 448 bits of the prime factor $q$. For a 1024-bit modulus $n$ where $q \approx \sqrt{n} \approx 2^{512}$, knowing 448 bits is more than enough to factor $n$ using **Coppersmith's Attack**.

## Exploitation
We define a polynomial $f(x) = x \cdot 2^{448} + (n \pmod{2^{448}})$ in the ring $\mathbb{Z}_n$.
We are looking for a small root $x_0 = q_{high}$ such that $f(x_0) = q$, which is a factor of $n$.
According to Coppersmith's theorem, we can find such a root if it is smaller than $n^{1/4}$.
Here $x_0 \approx 2^{512-448} = 2^{64}$, and $n^{1/4} \approx 2^{256}$, so the attack is guaranteed to work.

Using SageMath's `small_roots` method, we can efficiently find $q_{high}$, reconstruct $q$, factor $n$, and decrypt the flag.

## Flag
`sctf{PR0THess1on4l_pr1m3_leak3r}`

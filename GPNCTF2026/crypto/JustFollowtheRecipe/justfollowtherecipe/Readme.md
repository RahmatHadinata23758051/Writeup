# GPNCTF 2026 — Just Follow the Recipe Writeup

**Category:** Crypto  
**Challenge:** Just Follow the Recipe  
**Flag:** `GPNCTF{COMp1LEr5_ARE_Y0uR_Fr1eND_7Hey_WoU1D_nEV3r}`

---

## TL;DR

The challenge initially looks like a bounded modular linear algebra problem. The hidden recipe is a vector of 164 small decimal digits, and the service exposes hashes that are linear combinations modulo $12289$.

The actual bug is not in the mathematics alone. The binary behaves differently depending on which menu path is used. The source-level logic suggests a normal matrix multiplication routine, but the compiled binary uses inconsistent multiplication paths. By recovering the real linear maps used by the binary, combining the resulting modular equations, and solving the bounded system with lattice reduction, we can recover the secret recipe and submit it to obtain the flag.

---

## Challenge Overview

The service prints a target hash at startup and exposes this menu:

```
0) Check your work
1) Hash a single vector
2) Hash multiple vectors
3) Exit
```

The goal is to recover the hidden recipe vector $s$, then submit it through option `0`.

The recipe vector has length

$$m = 164.$$

Each coordinate is a decimal digit:

$$s_i \in \{0, 1, \dots, 9\}.$$

The hash output has length

$$n = 64.$$

The modulus is

$$q = 12289.$$

So the cryptographic core can be modeled as a modular linear map:

$$y = A s \pmod{q},$$

where

$$A \in \mathbb{Z}_q^{64 \times 164}, \quad s \in \{0,\dots,9\}^{164}, \quad y \in \mathbb{Z}_q^{64}.$$

At first glance, this is an underdetermined linear system over $\mathbb{Z}_q$. Since there are only 64 equations and 164 unknowns, direct modular linear algebra is not enough. The useful constraint is that every coordinate of $s$ is very small.

---

## Initial Analysis

The startup output gives a target vector

$$y = A s \pmod{12289}.$$

The service also allows us to hash user-controlled vectors. If the hash function were consistent across all menu paths, recovering the full matrix $A$ would be straightforward.

Let $e_j$ be the $j$-th standard basis vector:

$$e_j = (0,\dots,0,1,0,\dots,0).$$

Then $A e_j$ is exactly the $j$-th column of $A$.

Therefore, by querying the hash oracle on $e_0, e_1, \dots, e_{163}$, we should be able to recover the matrix column by column.

However, using menu option `1` for this failed. The recovered matrix looked valid, but it did not satisfy the target hash equation. That meant the failure was not caused by lattice reduction or bad parsing. **The oracle itself was inconsistent.**

---

## The Binary Was the Hint

The challenge description explicitly says:

> The binary is there for a reason, LOOK at it.

That was the key hint. The source-level logic suggests a normal hash operation based on matrix multiplication. The compiled binary, however, does not behave as if all menu options call the same linear map.

Empirically, the behavior is:

- Menu option `1` does **not** match the startup target hash path.
- Menu option `2` with $n = 1$ **matches** the startup target hash path.
- Menu option `2` with larger batches behaves differently again.

So the correct way to recover the matrix for the startup target is not:

```
1) Hash a single vector
```

but:

```
2) Hash multiple vectors
n = 1
```

This gives the matrix used by the target hash. I will call it $A_{\mathrm{multi}}$. It satisfies

$$y_{\mathrm{multi}} = A_{\mathrm{multi}} \, s \pmod{q}.$$

Menu option `1` is still useful, though. It gives another linear map, $A_{\mathrm{single}}$, together with another hash of the same secret:

$$y_{\mathrm{single}} = A_{\mathrm{single}} \, s \pmod{q}.$$

The bug gives us **two different systems** involving the same unknown bounded vector $s$.

---

## Recovering the Linear Maps

For every index $j$, query the corresponding oracle with $e_j$.

For the target-compatible path:

$$A_{\mathrm{multi}}[:,j] = H_{\mathrm{multi}}(e_j).$$

For the single-vector path:

$$A_{\mathrm{single}}[:,j] = H_{\mathrm{single}}(e_j).$$

After 164 basis queries for each path, we recover

$$A_{\mathrm{multi}} \in \mathbb{Z}_q^{64 \times 164} \quad \text{and} \quad A_{\mathrm{single}} \in \mathbb{Z}_q^{64 \times 164}.$$

The first system is

$$A_{\mathrm{multi}} \, s \equiv y_{\mathrm{multi}} \pmod{q}.$$

The second system is

$$A_{\mathrm{single}} \, s \equiv y_{\mathrm{single}} \pmod{q}.$$

Combining both systems gives

$$A' s \equiv y' \pmod{q},$$

where

$$A' = \begin{bmatrix} A_{\mathrm{multi}} \\ A_{\mathrm{single}} \end{bmatrix} \in \mathbb{Z}_q^{128 \times 164}, \qquad y' = \begin{bmatrix} y_{\mathrm{multi}} \\ y_{\mathrm{single}} \end{bmatrix} \in \mathbb{Z}_q^{128}.$$

In the solved instance, the combined matrix still did not have full rank. The observed rank was **94 out of 164**. Even so, the added constraints were enough to make the bounded solution recoverable with lattice reduction.

---

## Turning the Problem into a Lattice Problem

We need to solve

$$A' s \equiv y' \pmod{q}$$

with

$$0 \leq s_i \leq 9.$$

Equivalently, there exists an integer vector $k$ such that

$$A' s - y' = q k.$$

Rearranging:

$$A' s - q k = y'.$$

This is a **bounded modular linear system**. The vector $s$ is not random over $\mathbb{Z}_q^{164}$; it is inside a tiny box:

$$s \in [0,9]^{164} \cap \mathbb{Z}^{164}.$$

First, compute one modular solution $x_0$ to

$$A' x \equiv y' \pmod{q}.$$

All modular solutions can then be written as

$$x = x_0 + z,$$

where $z \in \ker(A' \bmod q)$. Define the kernel lattice

$$\Lambda = \left\{ z \in \mathbb{Z}^{164} : A' z \equiv 0 \pmod{q} \right\}.$$

Then the target secret is the vector in the affine lattice $x_0 + \Lambda$ that lies inside the box $[0,9]^{164}$.

The center of this box is

$$c = \left(\frac{9}{2}, \frac{9}{2}, \dots, \frac{9}{2}\right).$$

Therefore, the recovery problem becomes a closest vector style problem:

$$\text{find } x \in x_0 + \Lambda \text{ such that } \|x - c\| \text{ is small.}$$

Once such an $x$ is found, we check whether all coordinates are valid digits and whether both modular systems are satisfied.

---

## Lattice Construction

The lattice is

$$\Lambda = \ker_q(A').$$

A basis $B$ for $\Lambda$ can be built by computing the right kernel of $A'$ modulo $q$, then lifting the basis vectors to integer vectors.

After that, reduce the basis with LLL and BKZ:

$$B_{\mathrm{red}} = \operatorname{BKZ}\!\left(\operatorname{LLL}(B)\right).$$

Then use **Babai's nearest-plane algorithm** to find a lattice vector $v \in \Lambda$ such that

$$x_0 + v \approx c.$$

The candidate is accepted only if

$$s_i \in \{0,\dots,9\} \quad \text{for all } i,$$

and

$$A_{\mathrm{multi}} \, s \equiv y_{\mathrm{multi}} \pmod{q},$$

and

$$A_{\mathrm{single}} \, s \equiv y_{\mathrm{single}} \pmod{q}.$$

If all checks pass, the recovered vector is submitted to the service.

---

## Why the First Attempts Failed

### Wrong oracle path

Using menu option `1` to recover $A$ does not match the initial target hash. This creates a clean-looking but wrong system.

### Batched menu option 2 queries

Menu option `2` is only safe when used with $n = 1$. Larger batches trigger different behavior and give a matrix that does not match the startup target.

The safe path is:

```
menu 2
n = 1
```

for each basis vector.

### One hash was not enough

Using only

$$A_{\mathrm{multi}} \, s \equiv y_{\mathrm{multi}} \pmod{q}$$

left too much ambiguity. Lattice reduction could produce candidates that looked geometrically close but failed verification.

The final solver used both maps: $A_{\mathrm{multi}}$ and $A_{\mathrm{single}}$. This gave enough constraints for BKZ and Babai nearest-plane to recover the correct bounded vector.

---

## Solver Outline

The final solver performs the following steps:

1. Start the process locally or connect to the remote service.
2. Parse the startup target hash $y_{\mathrm{multi}}$.
3. Query menu option `1` to obtain the additional secret hash $y_{\mathrm{single}}$.
4. Recover $A_{\mathrm{multi}}$ using menu option `2` with $n = 1$.
5. Recover $A_{\mathrm{single}}$ using menu option `1`.
6. Build the combined system $A' s \equiv y' \pmod{q}$.
7. Compute a modular solution $x_0$ and the kernel lattice $\Lambda$.
8. Run LLL and BKZ.
9. Apply Babai nearest-plane around the box center $c = (9/2,\dots,9/2)$.
10. Verify the candidate against both systems.
11. Submit the recovered recipe vector.

A successful run looks like this:

```
[+] target hash parsed
[+] extra single-path secret hash parsed
[+] recovered multi 164/164 columns
[+] recovered single 164/164 columns
[+] building combined q-ary lattice
[+] combined rank 94 / 164
[+] fpylll LLL done
[+] fpylll BKZ-20 done
[+] Babai center=9/2
[+] Babai solved center=9/2
[+] secret = ...
Impossible the recipe was a lie.
```

The line `Impossible the recipe was a lie.` is the **success path** in the binary. Locally, the flag only appears if the `FLAG` environment variable is set. On the remote service, the same success path prints the real flag.

---

## Final Flag

```
GPNCTF{COMp1LEr5_ARE_Y0uR_Fr1eND_7Hey_WoU1D_nEV3r}
```

---

## Takeaway

The challenge was not just a generic lattice problem. The main trick was noticing that the compiled binary did not behave like the clean source-level model.

The important implementation-level lesson is:

$$\text{same-looking hash API} \neq \text{same linear map}.$$

Once the real maps used by the binary were recovered, the rest became a bounded modular lattice recovery problem.

The flag summarizes the bug nicely:

```
COMp1LEr5_ARE_Y0uR_Fr1eND_7Hey_WoU1D_nEV3r
```
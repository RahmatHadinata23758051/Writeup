# Writeup — Bonded Ledger

## Deskripsi Challenge

Challenge ini menyediakan service interaktif bernama **Bonded Ledger**. Saat terhubung ke service, kita diberikan public key dalam bentuk JSON yang berisi:

```text
q
n
A
t
```

Service menyediakan beberapa command:

```text
public
seal
getflag
help
exit
```

Tujuan challenge adalah mendapatkan flag dengan command `getflag`. Namun, command tersebut meminta kita mengirim **private seal**, yaitu secret vector yang digunakan pada proses key generation.

---

## Analisis Source Code

Dari file `chall.py`, parameter utama challenge adalah:

```python
Q = 3329
N = 70
```

Jadi modulus yang digunakan adalah `3329`, dan dimensi vektor/matriks adalah `70`.

Secret dibuat menggunakan fungsi `sample_noise(N)`:

```python
def sample_noise(width: int) -> list[int]:
    return [secrets.randbits(1) - secrets.randbits(1) for _ in range(width)]
```

Karena `secrets.randbits(1) - secrets.randbits(1)` hanya menghasilkan nilai `-1`, `0`, atau `1`, maka secret adalah vektor ternary sepanjang 70.

```text
secret[i] ∈ {-1, 0, 1}
```

---

## Key Generation

Fungsi `keygen()` membuat:

```python
secret = sample_noise(N)
matrix = [[secrets.randbelow(Q) for _ in range(N)] for _ in range(N)]
error = sample_noise(N)
matrix_secret = multiply_matrix_vector(matrix, secret)
public = [(matrix_secret[index] + error[index]) % Q for index in range(N)]
```

Secara matematis, public key dihitung sebagai:

```text
t = A*s + e mod q
```

dengan:

```text
A = public matrix
s = secret ternary vector
e = small error ternary vector
q = 3329
n = 70
```

Ini adalah bentuk sederhana dari problem **Learning With Errors** atau LWE.

---

## Fungsi Seal

Command `seal` mengenkripsi satu byte note menggunakan public key:

```python
nonce = sample_noise(N)
vector_error = sample_noise(N)
scalar_error = sample_noise(1)[0]
matrix_nonce = multiply_matrix_vector(matrix, nonce)
wrapped_vector = [(matrix_nonce[index] + vector_error[index]) % Q for index in range(N)]
wrapped_note = (dot(public, nonce) + scalar_error + note) % Q
```

Namun untuk challenge ini, oracle `seal` tidak perlu digunakan. Yang dibutuhkan adalah mendapatkan `secret`.

---

## Validasi Flag

Command `getflag` meminta input berupa JSON list atau space-separated ternary vector.

Program memvalidasi input dengan fungsi `parse_secret_guess()`. Panjang input harus tepat `N = 70`, dan setiap elemen harus bernilai `-1`, `0`, atau `1`.

Jika input sama dengan secret asli, service akan mengeluarkan flag:

```python
if guess == secret:
    write_output(f"Archive copy released. {get_flag()}\n")
```

Jadi target eksploitasi adalah melakukan recovery secret `s` dari public key `A` dan `t`.

---

## Ide Penyelesaian

Kita punya persamaan:

```text
t = A*s + e mod q
```

dengan:

```text
s ∈ {-1,0,1}^70
e ∈ {-1,0,1}^70
```

Karena secret dan error sangat kecil, problem ini dapat diselesaikan dengan lattice reduction menggunakan **LLL**.

Kita ingin mencari vektor pendek:

```text
A*s - q*k - t = -e
```

Karena `s` dan `e` kecil, vektor:

```text
[-e | s | -1]
```

akan menjadi vektor pendek di lattice.

---

## Konstruksi Lattice

Basis lattice dibuat dengan bentuk:

```text
[A_col_j | unit_j | 0]
[q*I     | 0      | 0]
[t       | 0      | 1]
```

Jika mengambil kombinasi linear yang sesuai, kita mendapatkan:

```text
A*s - q*k - t = -e
```

Sehingga hasil LLL akan mengandung vektor pendek yang bagian tengahnya adalah secret `s`.

---

## Solver

Berikut solver menggunakan Sage:

```python
import socket, ssl, json, re

HOST = "tcp-01kz0jvqfnkqj6z4m970hk9gxs.u-ctf-ctf-7001b39a.urc.tf"
PORT = int(443)

def recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

raw = socket.create_connection((str(HOST), int(PORT)))
ctx = ssl.create_default_context()
sock = ctx.wrap_socket(raw, server_hostname=HOST)

banner = recv_until(sock, b"ledger> ")
m = re.search(br"public = (\{[^\n]+\})", banner)
assert m, "public json not found"

pub = json.loads(m.group(1).decode())
q = pub["q"]
n = pub["n"]
A = pub["A"]
t = pub["t"]

B = Matrix(ZZ, 2*n + 1, 2*n + 1)

for j in range(n):
    for i in range(n):
        B[j, i] = A[i][j]
    B[j, n + j] = 1

for i in range(n):
    B[n + i, i] = q

for i in range(n):
    B[2*n, i] = t[i]

B[2*n, 2*n] = 1

print("[+] running LLL...")
L = B.LLL()
print("[+] LLL done")

secret = None

for row in L.rows():
    v = [int(x) for x in row]

    if abs(v[-1]) != 1:
        continue

    middle = v[n:2*n]

    for cand in (middle, [-x for x in middle]):
        if not all(x in (-1, 0, 1) for x in cand):
            continue

        ok = True
        for i in range(n):
            val = sum(A[i][j] * cand[j] for j in range(n)) - t[i]
            centered = ((val + q//2) % q) - q//2

            if centered not in (-1, 0, 1):
                ok = False
                break

        if ok:
            secret = cand
            break

    if secret is not None:
        break

assert secret is not None, "secret not found"

print("[+] secret =", secret)

sock.sendall(b"getflag\n")
recv_until(sock, b"Private seal")
sock.sendall(json.dumps(secret).encode() + b"\n")

print(recv_until(sock, b"\n").decode(errors="ignore"))
```

---

## Menjalankan Solver

Solver dijalankan dengan Sage:

```bash
sage solve.sage
```

Output:

```text
[+] running LLL...
[+] LLL done
[+] secret = [1, 0, 0, 0, 0, -1, 1, 0, -1, 0, 0, 0, 1, 1, 1, -1, 0, 0, 1, -1, 0, 0, -1, -1, 1, -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 1, 1, 0, 0, 0, 1, -1, 0, 1, 0, 0, -1, 0, 0, 0, 1, 0, 1, 0, 1, 0, -1, 0, 1, 0, -1, 1, 0, 0, 0, 1, 0, 0]
Archive copy released. uctf{0573790ba8bad1a4a11c6d9fc1882759198f}
```

---

## Flag

```text
uctf{0573790ba8bad1a4a11c6d9fc1882759198f}
```

---


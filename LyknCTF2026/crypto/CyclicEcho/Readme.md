# Cyclic Echo

**Category:** Crypto  
**CTF:** LYKN CTF 2026  
**Flag:** `LYKNCTF{63da0d1a9d434cc49844f44546da982c}`

## Description

> A signal keeps repeating, echoing back on itself in a loop no one can quite explain. Listen closely enough, and the echo gives away where it came from.

Service mengirim public key NTRU, leak sederhana dari private polynomial, lalu flag yang dienkripsi memakai AES-GCM.

Sekilas jalurnya terlihat seperti recovery private key NTRU. Ternyata nggak perlu.

## Analisis

Key AES dibentuk dari:

```python
s_alg = sum((i + 1) * f[i] * g[i] for i in range(N)) % Q_PRIME
```

Parameter yang dipakai:

```python
Q_PRIME = 4099
```

Lalu `s_alg` masuk ke HKDF bersama nilai publik `N` dan `Q`:

```python
ikm = (
    s_alg.to_bytes(2, "big")
    + N.to_bytes(2, "big")
    + Q.to_bytes(2, "big")
)

key = HKDF(
    master=ikm,
    key_len=32,
    salt=salt,
    hashmod=SHA256,
    context=b"lyknctf-2026",
)
```

Karena `s_alg` direduksi modulo `4099`, ruang rahasianya hanya:

```text
0 <= s_alg < 4099
```

Jadi cukup brute-force 4099 kandidat. Public key NTRU dan side-channel leak tidak dibutuhkan.

Setiap kandidat dipakai untuk menurunkan key AES. Tag GCM menjadi oracle validasi:

```python
cipher.decrypt_and_verify(ciphertext, tag)
```

Key salah selalu gagal verifikasi. Key benar langsung membuka flag.

## Solver

```python
#!/usr/bin/env python3
import json
import socket
import sys

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF


DEFAULT_HOST = "51.79.140.18"
DEFAULT_PORT = 19705
KDF_INFO = b"lyknctf-2026"


def recv_instance(host: str, port: int) -> dict:
    data = b""

    with socket.create_connection((host, port), timeout=10) as sock:
        sock.settimeout(3)

        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break

            if not chunk:
                break

            data += chunk

            start = data.find(b"{")
            end = data.rfind(b"}")

            if start != -1 and end > start:
                try:
                    return json.loads(data[start:end + 1])
                except json.JSONDecodeError:
                    pass

    start = data.find(b"{")
    end = data.rfind(b"}")

    if start == -1 or end <= start:
        raise RuntimeError("Remote tidak mengirim JSON valid")

    return json.loads(data[start:end + 1])


def derive_key(s_alg: int, n: int, q: int, salt: bytes) -> bytes:
    ikm = (
        s_alg.to_bytes(2, "big")
        + n.to_bytes(2, "big")
        + q.to_bytes(2, "big")
    )

    return HKDF(
        master=ikm,
        key_len=32,
        salt=salt,
        hashmod=SHA256,
        context=KDF_INFO,
    )


def solve(instance: dict) -> tuple[int, bytes]:
    params = instance["parameters"]
    encrypted = instance["encrypted_flag"]

    n = int(params["N"])
    q = int(params["q"])
    q_prime = int(params["q_prime"])

    salt = bytes.fromhex(encrypted["salt"])
    nonce = bytes.fromhex(encrypted["nonce"])
    ciphertext = bytes.fromhex(encrypted["ciphertext"])
    tag = bytes.fromhex(encrypted["tag"])

    for s_alg in range(q_prime):
        key = derive_key(s_alg, n, q, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            continue

        return s_alg, plaintext

    raise RuntimeError("Tidak ada kandidat valid")


def main():
    host = sys.argv[1] if len(sys.argv) >= 2 else DEFAULT_HOST
    port = int(sys.argv[2]) if len(sys.argv) >= 3 else DEFAULT_PORT

    instance = recv_instance(host, port)
    s_alg, plaintext = solve(instance)

    print(f"[+] s_alg = {s_alg}")
    print(f"[+] flag  = {plaintext.decode()}")


if __name__ == "__main__":
    main()
```

## Eksekusi

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py 51.79.140.18 19705
```

Output remote:

```text
[+] flag  = LYKNCTF{63da0d1a9d434cc49844f44546da982c}
```

## Kesimpulan

Lapisan NTRU cuma distraksi. Seluruh secret untuk KDF dipadatkan menjadi satu integer modulo 4099, sehingga effective key space jatuh ke 4099 kemungkinan.

AES-GCM membuat brute-force makin gampang karena tag autentikasinya langsung membedakan key benar dan salah.

# Headache Writeup

## Flag

```text
ASIS{c0uPleD_n0nL1n3Ar_Dynam!c5_R3c0vEry_v1A_p0l3s_&_l34st_squ4r3s!!}
```

## Ringkasan

Server memberi oracle untuk fungsi numerik rahasia. Setiap ronde punya parameter baru:

```python
coupling_tensors = np.random.uniform(0.5, 2.0, size=(3, 4, 4))
observable_vectors = np.random.uniform(0.5, 2.0, size=(3, 4))
```

Total parameter rahasia:

```text
A = 3 * 4 * 4 = 48
B = 3 * 4     = 12
Total         = 60 parameter
```

Kita boleh query oracle sampai 1200 kali per ronde. Karena modelnya cuma punya 60 parameter real, cukup ambil sekitar 96 sampel, fit parameternya dengan least squares, lalu pakai model lokal buat menjawab challenge.

## Analisis Fungsi Oracle

Fungsi utama server:

```python
def evaluate_ensemble(X, coupling_tensors, observable_vectors):
    X = np.array(X, dtype=np.float64)
    x_tail = X[-1]
    total_energy = 0.0

    for c in range(NUM_CHANNELS):
        microstate_energies = np.einsum('j,jk,ik->i', x_tail, coupling_tensors[c].T, X)

        gauge_shift = np.max(microstate_energies)
        boltzmann_weights = np.exp(microstate_energies - gauge_shift)
        partition_fn = np.sum(boltzmann_weights)

        observables = np.dot(X, observable_vectors[c])
        ensemble_expectation = np.dot(boltzmann_weights, observables) / partition_fn
        total_energy += float(ensemble_expectation)

    return total_energy
```

Dari `einsum`:

```text
microstate_energies_i = X_i · (A_c @ x_tail)
```

Lalu server menghitung softmax terhadap energy itu:

```text
p_i = exp(e_i) / sum(exp(e_i))
```

Observable per baris:

```text
o_i = X_i · B_c
```

Output untuk satu channel:

```text
F_c(X) = Σ p_i o_i
```

Output final:

```text
F(X) = F_0(X) + F_1(X) + F_2(X)
```

Jadi ini bukan PRF yang sulit. Ini model parametrik kecil yang bisa dipelajari langsung dari query oracle.

## Strategi Attack

Target per ronde:

1. Selesaikan proof-of-work.
2. Kirim banyak query `eval <json_matrix>`.
3. Simpan pasangan `(X, tag)`.
4. Fit parameter rahasia `A` dan `B` menggunakan `scipy.optimize.least_squares`.
5. Minta `challenge`.
6. Hitung tag challenge secara lokal dari parameter hasil fitting.
7. Kirim `verify <json_tags>`.
8. Ulangi sampai 7 ronde.

Karena `TOLERANCE = 1e-6`, fitting harus cukup akurat. Dengan 96 query panjang 20, hasil fitting stabil sampai error sekitar `1e-15`.

## Kenapa 96 Query Cukup

Jumlah parameter hanya 60. Setiap query menghasilkan satu persamaan real:

```text
tag = F(X; A, B)
```

Kalau query kurang dari jumlah parameter, model bisa ambigu. Dengan 96 query, sistemnya overdetermined:

```text
96 data > 60 parameter
```

Least squares bisa menemukan parameter yang konsisten dengan oracle.

Panjang sequence dipakai `20` supaya tiap query membawa informasi lebih kuat. Walaupun satu query tetap cuma menghasilkan satu tag, struktur softmax-nya lebih kaya dibanding sequence pendek.

## Jacobian Analitik

Agar fitting cepat, solver tidak memakai numerical gradient. Jacobian dihitung langsung.

Untuk satu channel:

```text
F_c = Σ p_i o_i
```

Turunan terhadap observable vector `B_c`:

```text
∂F_c / ∂B_c = Σ p_i X_i
```

Turunan terhadap energy:

```text
∂F_c / ∂e_i = p_i (o_i - F_c)
```

Karena:

```text
e_i = X_i · (A_c @ x_tail)
```

maka:

```text
∂F_c / ∂A_c = (Σ g_i X_i) outer x_tail
```

dengan:

```text
g_i = p_i (o_i - F_c)
```

Jacobian analitik ini bikin fitting per ronde selesai sekitar `0.02s - 0.07s`.

## Optimasi Waktu

Versi awal pakai 300 query per ronde dan print setiap query. Itu terlalu lambat, karena server punya delay:

```python
QUERY_DELAY_SEC = 0.03
```

Kalau 300 query per ronde:

```text
300 * 7 * 0.03 = 63 detik
```

Belum termasuk fitting dan network overhead. Koneksi bisa keburu ditutup.

Solver final memakai:

```python
N_TRAIN = 96
```

Semua query juga dikirim secara batch/pipeline:

```python
for X in Xs:
    send(sock, "eval " + json.dumps(X.tolist(), separators=(",", ":")))

for _ in range(len(Xs)):
    obj = recv_json(f)
```

Ini mengurangi overhead komunikasi dan terminal tidak spam.

## Hasil Run

```bash
python3 solve.py 65.109.208.91 1337
```

Output:

```text
[+] POW ok
[+] round 1/7: querying 96
[+] round 1/7: fitting
    train_err=1.776e-15, fit_time=0.04s
[+] Round 1 authenticated! (max_err=3.55e-15)

...

[+] round 7/7: querying 96
[+] round 7/7: fitting
    train_err=3.553e-15, fit_time=0.04s
<FLAG>ASIS{c0uPleD_n0nL1n3Ar_Dynam!c5_R3c0vEry_v1A_p0l3s_&_l34st_squ4r3s!!}</FLAG>
```

## Solver

```python
#!/usr/bin/env python3
import socket
import sys
import json
import hashlib
import itertools
import time
import numpy as np
from scipy.optimize import least_squares

HOST = sys.argv[1] if len(sys.argv) > 1 else "65.109.208.91"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337

NUM_CHANNELS = 3
DIM = 4
NUM_ROUNDS = 7

N_TRAIN = 96
TRAIN_LEN = 20
RESTARTS = 8

def log(s):
    print(s, flush=True)

def recv_json(f, want_status=None):
    while True:
        line = f.readline()
        if not line:
            raise EOFError("connection closed")

        s = line.decode(errors="ignore").strip()
        if not s:
            continue

        try:
            obj = json.loads(s)
        except Exception:
            continue

        if want_status is None or obj.get("status") == want_status:
            return obj

def send(sock, s):
    sock.sendall((s + "\n").encode())

def solve_pow(prefix, bits):
    target = "0" * (bits // 4)
    for i in itertools.count():
        nonce = str(i)
        if hashlib.sha256((prefix + nonce).encode()).hexdigest().startswith(target):
            return nonce

def batch_eval(sock, f, Xs):
    for X in Xs:
        send(sock, "eval " + json.dumps(X.tolist(), separators=(",", ":")))

    ys = []
    for _ in range(len(Xs)):
        obj = recv_json(f)
        if obj.get("status") != "ok":
            raise RuntimeError(obj)
        ys.append(float(obj["tag"]))

    return np.asarray(ys, dtype=np.float64)

def pred_jac_batch(params, Xs):
    A = params[:48].reshape(NUM_CHANNELS, DIM, DIM)
    B = params[48:].reshape(NUM_CHANNELS, DIM)

    N, L, _ = Xs.shape
    xt = Xs[:, -1, :]

    vals = np.zeros(N, dtype=np.float64)
    J = np.zeros((N, 60), dtype=np.float64)

    for c in range(NUM_CHANNELS):
        v = xt @ A[c].T
        e = np.einsum("nld,nd->nl", Xs, v)
        e -= np.max(e, axis=1, keepdims=True)

        w = np.exp(e)
        p = w / np.sum(w, axis=1, keepdims=True)

        obs = Xs @ B[c]
        fc = np.sum(p * obs, axis=1)
        vals += fc

        J[:, 48 + 4*c : 48 + 4*(c+1)] = np.einsum("nl,nld->nd", p, Xs)

        g = p * (obs - fc[:, None])
        gv = np.einsum("nl,nld->nd", g, Xs)
        grad_A = gv[:, :, None] * xt[:, None, :]
        J[:, 16*c : 16*(c+1)] = grad_A.reshape(N, 16)

    return vals, J

def fit_model(Xs, ys, round_no):
    def fun(p):
        pred, _ = pred_jac_batch(p, Xs)
        return pred - ys

    def jac(p):
        _, J = pred_jac_batch(p, Xs)
        return J

    best_err = 1e100
    best_p = None

    for r in range(RESTARTS):
        rng = np.random.default_rng(0xBADC0DE + round_no * 1000 + r)
        p0 = np.concatenate([
            rng.uniform(0.5, 2.0, 48),
            rng.uniform(0.5, 2.0, 12),
        ])

        res = least_squares(
            fun,
            p0,
            jac=jac,
            method="lm",
            max_nfev=220,
            xtol=1e-10,
            ftol=1e-10,
            gtol=1e-10,
            x_scale="jac",
        )

        err = float(np.max(np.abs(res.fun)))
        if err < best_err:
            best_err = err
            best_p = res.x

        if err < 1e-8:
            break

    return best_p, best_err

def local_eval(X, params):
    A = params[:48].reshape(NUM_CHANNELS, DIM, DIM)
    B = params[48:].reshape(NUM_CHANNELS, DIM)

    X = np.asarray(X, dtype=np.float64)
    xt = X[-1]

    total = 0.0
    for c in range(NUM_CHANNELS):
        e = X @ (A[c] @ xt)
        e -= np.max(e)

        w = np.exp(e)
        p = w / np.sum(w)

        obs = X @ B[c]
        total += float(p @ obs)

    return total

def make_train(round_no):
    rng = np.random.default_rng(1337 + round_no)
    return rng.uniform(-1.0, 1.0, size=(N_TRAIN, TRAIN_LEN, DIM)).astype(np.float64)

def solve_round(sock, f, round_no):
    log(f"[+] round {round_no}/7: querying {N_TRAIN}")

    Xs = make_train(round_no)
    ys = batch_eval(sock, f, Xs)

    log(f"[+] round {round_no}/7: fitting")
    t0 = time.time()
    params, err = fit_model(Xs, ys, round_no)
    log(f"    train_err={err:.3e}, fit_time={time.time() - t0:.2f}s")

    send(sock, "challenge")
    chall = recv_json(f, "challenge")

    preds = [local_eval(X, params) for X in chall["sequences"]]
    send(sock, "verify " + json.dumps(preds, separators=(",", ":")))

    res = recv_json(f)
    if res.get("status") != "ok":
        raise RuntimeError(res)

    if "flag" in res:
        print("<FLAG>" + res["flag"] + "</FLAG>", flush=True)
        return True

    log("[+] " + res.get("message", "round passed"))
    return False

def main():
    sock = socket.create_connection((HOST, PORT), timeout=10)

    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass

    sock.settimeout(120)
    f = sock.makefile("rb")

    pow_req = recv_json(f, "pow_request")
    nonce = solve_pow(pow_req["prefix"], int(pow_req["difficulty_bits"]))
    send(sock, nonce)
    recv_json(f, "pow_ok")
    log("[+] POW ok")

    for r in range(1, NUM_ROUNDS + 1):
        if solve_round(sock, f, r):
            return

if __name__ == "__main__":
    main()
```

```
FLAG
ASIS{c0uPleD_n0nL1n3Ar_Dynam!c5_R3c0vEry_v1A_p0l3s_&_l34st_squ4r3s!!}
```


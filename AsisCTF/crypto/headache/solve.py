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

# 96 udah cukup stabil di simulasi dan jauh lebih cepat dari 300.
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
    # Kirim semua eval dulu biar hemat round-trip.
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
    # Xs shape: N x L x 4
    A = params[:48].reshape(NUM_CHANNELS, DIM, DIM)
    B = params[48:].reshape(NUM_CHANNELS, DIM)

    N, L, _ = Xs.shape
    xt = Xs[:, -1, :]

    vals = np.zeros(N, dtype=np.float64)
    J = np.zeros((N, 60), dtype=np.float64)

    for c in range(NUM_CHANNELS):
        # server: e_i = X_i dot (A_c @ x_tail)
        v = xt @ A[c].T
        e = np.einsum("nld,nd->nl", Xs, v)
        e -= np.max(e, axis=1, keepdims=True)

        w = np.exp(e)
        p = w / np.sum(w, axis=1, keepdims=True)

        obs = Xs @ B[c]
        fc = np.sum(p * obs, axis=1)
        vals += fc

        # dF / dB_c
        J[:, 48 + 4*c : 48 + 4*(c+1)] = np.einsum("nl,nld->nd", p, Xs)

        # dF / dA_c
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

    if err > 1e-5:
        log("    bad fit, but still trying challenge")

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

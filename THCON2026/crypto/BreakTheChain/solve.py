#!/usr/bin/env python3
import socket

HOST = "4.178.152.74"
PORT = 9000

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed prematurely.")
        buf += chunk
    return buf

def recv_prefixed(sock: socket.socket) -> bytes:
    length_bytes = _recv_exact(sock, 4)
    length = int.from_bytes(length_bytes, "big")
    return length_bytes + _recv_exact(sock, length)

def send_prefixed(sock: socket.socket, data: bytes) -> None:
    sock.sendall(len(data).to_bytes(4, "big") + data)

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        data = recv_prefixed(sock)
        
        # The payload contains [num_actions] + [actions...]
        # Action 1 starts at index 4 of the payload (excluding length prefix)
        # Flipping the first bit of the first action triggers the autodelete command.
        
        payload = list(data[4:])
        payload[4] ^= 0x01
        
        send_prefixed(sock, bytes(payload))
        
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except Exception:
                break
        print(response.decode("utf-8", errors="ignore"))

if __name__ == "__main__":
    main()

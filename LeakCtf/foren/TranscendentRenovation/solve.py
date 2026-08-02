#!/usr/bin/env python3
import socket
import ssl

HOST = "transcendent-renovation.instances.ctf.l3ak.team"
PORT = 1337

answers = {
    1: "OLE CF",
    2: "f01b4d95cf55d32a.automaticDestinations-ms",
    3: r"\\TSCLIENT\HAUNTEDHOUSE",
    4: "46",
    5: "EC2AB952-7E4D-11F1-89AD-A2DEAD7852AD",
    6: "logging-vm",
    7: "SoulSearching",
}

def recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("server closed the connection")
        data += chunk
    return data

def main():
    ctx = ssl.create_default_context()
    with socket.create_connection((HOST, PORT)) as raw:
        with ctx.wrap_socket(raw, server_hostname=HOST) as sock:
            for number, answer in answers.items():
                recv_until(sock, b"Enter question number to answer:")
                sock.sendall(f"{number}\n".encode())
                recv_until(sock, b"Enter your answer:")
                sock.sendall(f"{answer}\n".encode())
            print(sock.recv(8192).decode(errors="replace"))

if __name__ == "__main__":
    main()

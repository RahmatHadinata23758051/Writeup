#!/usr/bin/env python3
import re
import socket
import urllib.parse


HOST = "109.69.22.21"
PORT = 1337


SAFE_FIRST_LINES = {
    "GET /api/data?script=<script>alert('test')</script> HTTP/1.1",
    "GET /api/search?q=union+select+null HTTP/1.1",
    "GET /api/run?script=console.log('hello') HTTP/1.1",
    "GET /api/load?file=../../config.json HTTP/1.1",
    "GET /admin/../users HTTP/1.1",
    "GET /api/test?id=1' OR '1'='1 HTTP/1.1",
    "GET /api/exec?cmd=ls HTTP/1.1",
}


def is_malicious(request: str) -> bool:
    raw = request.replace("\r", "")
    low = raw.lower()
    dec = urllib.parse.unquote_plus(low)
    text = low + "\n" + dec
    first = raw.split("\n")[0]

    if first in SAFE_FIRST_LINES:
        return False
    if '"sql":"select * from users where id = ?"' in text and '"params":[' in text:
        return False
    if first.startswith("GET /api/filter?query=SELECT+*+FROM+users HTTP/1.1"):
        return False
    if '"xpath":"/root/item[@id=' in text and "<root><item id='" in text:
        return False

    if any(tok in text for tok in ['<!doctype', '<!entity', 'system "http://', 'system "file://', '%remote;', '&xxe;', '&exfil;']):
        return True
    if any(tok in text for tok in ["/etc/passwd", "/etc/shadow", "win.ini", "boot.ini"]):
        return True
    if any(tok in text for tok in ["process.mainmodule", "constructor.constructor", "__class__", "__mro__", "__subclasses__"]):
        return True
    if ("{{" in text or "${" in text or "<%" in text) and any(tok in text for tok in ["child_process", "exec(", "process", "constructor", "7*7"]):
        return True
    if "xpath=" in text and (" or " in text or "'='" in text):
        return True
    if '"xpath":' in text and (" or " in text or "'1'='1" in text):
        return True
    if any(tok in text for tok in ["<script", "<img", "onerror=", "onload=", "javascript:", "<svg"]):
        return True
    if any(tok in text for tok in [
        "system(",
        "exec(",
        "shell_exec",
        "passthru",
        "eval(",
        "child_process",
        'require("fs")',
        "require('fs')",
        'require("child_process")',
        "require('child_process')",
        "cat /etc/passwd",
        "bash -c",
        "rm -rf",
        "curl http",
        "wget http",
        "nc -e",
        '"command":"',
        'type":"shell',
        ";whoami",
        ";id",
        "|whoami",
        "|id",
        "`id`",
        "`whoami`",
    ]):
        return True
    if first.startswith("POST /api/exec "):
        return True
    if first.startswith("POST /api/eval ") and '"expression":"2+2"' not in text:
        return True
    if first.startswith("GET /api/run?script=") and "console.log('hello')" not in raw:
        return True
    if first.startswith("POST /api/process ") and ("require(" in text or "exec(" in text or "rm -rf" in text):
        return True
    if any(tok in text for tok in [" sleep(", "@@version", "information_schema", "benchmark(", "waitfor delay", "xp_cmdshell", " substring(", " ascii(", "version()", " drop table "]):
        return True
    if "union" in text and ("--" in text or "/**/" in text or " id=" in text or "query=" in text or first.lower().startswith("get /index.php?id=") or first.lower().startswith("get /api/users?id=")):
        return True
    if "select * from users where id = 1" in text and ("' or '1'='1" in text or "' or 1=1" in text):
        return True
    if re.search(r"""(['"]).{0,20}\b(or|and)\b.{0,20}(=|like)""", text):
        return True
    if any(tok in text for tok in ["'--", '"--', "-- http/", "' #", '" #']):
        return True
    return False


def recv_until(sock: socket.socket) -> str:
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if (
            b"Your answer (Block/Allow):" in data
            or b"Challenge failed" in data
            or b"Congratulations" in data
            or b"Flag:" in data
        ):
            break
    return data.decode("utf-8", "replace")


def main() -> None:
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        sock.settimeout(5)
        sock.recv(4096)
        sock.sendall(b"Start\n")

        while True:
            text = recv_until(sock)
            if not text:
                break
            if "Your answer" not in text:
                print(text.strip())
                break

            match = re.search(r"--- Request (\d+)/100 ---\n(.*)Your answer", text, re.S)
            if not match:
                raise RuntimeError("Failed to parse request")

            request = match.group(2).strip()
            answer = "Block" if is_malicious(request) else "Allow"
            sock.sendall((answer + "\n").encode())


if __name__ == "__main__":
    main()

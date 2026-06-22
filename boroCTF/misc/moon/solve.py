#!/usr/bin/env python3
import re
import sys
import html
import requests

URLS = [
    "https://redlib.catsarch.com/r/Edgerunners/comments/1tneaip/just_finished_cyberpunk_for_the_first_time_i_feel/oo0icf5/",
    "https://redlib.perennialte.ch/r/Edgerunners/comments/1tneaip/just_finished_cyberpunk_for_the_first_time_i_feel/oo0icf5/",
    "https://redlib.r4fo.com/r/Edgerunners/comments/1tneaip/just_finished_cyberpunk_for_the_first_time_i_feel/oo0icf5/",
    "https://farside.link/redlib/r/Edgerunners/comments/1tneaip/just_finished_cyberpunk_for_the_first_time_i_feel/oo0icf5/",
]

ZW0 = "\u200b"  # zero width space
ZW1 = "\u200c"  # zero width non-joiner

def decode_bits(seq):
    for zero, one in [(ZW0, ZW1), (ZW1, ZW0)]:
        bits = seq.replace(zero, "0").replace(one, "1")

        for off in range(8):
            b = bits[off:]
            out = ""
            for i in range(0, len(b) - 7, 8):
                out += chr(int(b[i:i+8], 2))

            m = re.search(r"boroCTF\{[^}]+\}", out)
            if m:
                return m.group(0)

    return None

def extract_from_text(s):
    s = html.unescape(s)

    # kalau source menyimpan sebagai literal escape
    s = s.replace("\\u200b", ZW0).replace("\\u200c", ZW1)
    s = s.replace("&#8203;", ZW0).replace("&#8204;", ZW1)
    s = s.replace("&#x200b;", ZW0).replace("&#x200c;", ZW1)

    # Prioritas: hidden chars yang tepat di antara "Just" dan "finished"
    patterns = [
        rf"Just([{ZW0}{ZW1}]+)\s*finished",
        rf"Just\s*([{ZW0}{ZW1}]+)\s*finished",
    ]

    for pat in patterns:
        m = re.search(pat, s, flags=re.I)
        if m:
            flag = decode_bits(m.group(1))
            if flag:
                return flag

    # Fallback: ambil semua zero-width chars dari page
    seq = "".join(c for c in s if c in (ZW0, ZW1))
    if seq:
        return decode_bits(seq)

    return None

def main():
    if len(sys.argv) > 1:
        data = open(sys.argv[1], "r", encoding="utf-8", errors="ignore").read()
        flag = extract_from_text(data)
        print(flag or "flag not found")
        return

    headers = {
        "User-Agent": "Mozilla/5.0 ctf-solver",
        "Accept": "text/html,*/*",
    }

    for url in URLS:
        try:
            r = requests.get(url, headers=headers, timeout=20, allow_redirects=True)
            print(f"[*] {url}")
            print(f"    status={r.status_code} content-type={r.headers.get('content-type')}")
            flag = extract_from_text(r.text)
            if flag:
                print(flag)
                return
        except Exception as e:
            print(f"[!] failed: {e}")

    print("flag not found")
    print("Coba buka Redlib di browser, save HTML-nya sebagai page.html, lalu run:")
    print("python3 solve.py page.html")

if __name__ == "__main__":
    main()

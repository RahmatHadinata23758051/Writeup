#!/usr/bin/env python3
import base64
import re
import sys
import zipfile
from pathlib import Path


def b64decode_loose(s: str):
    """Decode a base64-ish string with missing padding. Return bytes or None."""
    s = s.strip()
    try:
        return base64.b64decode(s + "=" * ((4 - len(s) % 4) % 4), validate=False)
    except Exception:
        return None


def is_mostly_printable(bs: bytes) -> bool:
    if not bs:
        return False
    ok = sum(32 <= b < 127 or b in (9, 10, 13) for b in bs)
    return ok / len(bs) >= 0.80


def main() -> int:
    zip_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("chal.zip")
    if not zip_path.exists():
        # Handy fallback for this sandbox; normal CTF use is just: python3 solve.py chal.zip
        alt = Path("/mnt/data/chal.zip")
        if alt.exists():
            zip_path = alt
        else:
            print(f"missing archive: {zip_path}", file=sys.stderr)
            return 1

    decoded_strings = []
    raw_texts = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        for name in zf.namelist():
            if not name.lower().endswith((".js", ".json", ".html")):
                continue
            text = zf.read(name).decode("utf-8", errors="ignore")
            raw_texts.append((name, text))

            # Decode JS unicode escapes like \u0056\u0047... into normal text.
            normalized = text.encode("utf-8").decode("unicode_escape", errors="ignore")

            # Pull quoted/base64-looking tokens and test normal + reversed forms.
            tokens = set(re.findall(r"[A-Za-z0-9+/=]{8,}", normalized))
            for tok in tokens:
                for label, candidate in (("normal", tok), ("reversed", tok[::-1])):
                    out = b64decode_loose(candidate)
                    if out is not None and is_mostly_printable(out):
                        decoded_strings.append((name, tok, label, out.decode("latin1", errors="ignore")))

            # Some useful strings are already exposed in comments after unicode decoding.
            for m in re.finditer(r"(?:Thryve\{|_[A-Za-z0-9_]+\})[A-Za-z0-9_{}]*", normalized):
                decoded_strings.append((name, "direct", "direct", m.group(0)))

    # Find the flag prefix and suffix from decoded artifacts.
    prefix = None
    suffix = None
    for _name, _tok, _label, s in decoded_strings:
        m = re.search(r"Thryve\{[A-Za-z0-9_]+", s)
        if m:
            prefix = m.group(0)
        m = re.search(r"_[A-Za-z0-9_]+\}", s)
        if m:
            suffix = m.group(0)

    if not prefix or not suffix:
        print("decoded candidates:")
        for item in decoded_strings:
            print(item)
        print("flag pieces not found", file=sys.stderr)
        return 2

    flag = prefix + suffix
    print(f"<FLAG>{flag}</FLAG>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


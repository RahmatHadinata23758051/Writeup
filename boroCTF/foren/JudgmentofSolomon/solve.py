#!/usr/bin/env python3
from pathlib import Path
import re

DATA = Path(__file__).with_name('code')


def main():
    blob = DATA.read_text(errors='ignore')
    m = re.search(r'boroCTF\{[^}\r\n]*\}', blob)
    if not m:
        raise SystemExit('flag not found')
    print(m.group(0))


if __name__ == '__main__':
    main()

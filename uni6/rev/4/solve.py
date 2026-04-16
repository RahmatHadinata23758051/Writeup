#!/usr/bin/env python3
import re
import subprocess
from pathlib import Path

BIN = Path(__file__).with_name('sentinel')
PASS = 'JBzm9#ls2#hd8]'


def main() -> None:
    proc = subprocess.run(
        [str(BIN)],
        input=PASS + '\n',
        text=True,
        capture_output=True,
        check=False,
    )
    out = (proc.stdout or '') + (proc.stderr or '')
    m = re.search(r"uni6\{[^}]+\}", out)
    if not m:
        raise SystemExit('flag not found')
    print(m.group(0))


if __name__ == '__main__':
    main()

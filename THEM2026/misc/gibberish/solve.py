#!/usr/bin/env python3
from pathlib import Path
import sys

POW10 = 3 ** 10
POW9 = 3 ** 9
OPS_VALID = {4, 5, 23, 39, 40, 62, 68, 81}
TABLE_CRAZY = (
    (1, 0, 0),
    (1, 0, 2),
    (2, 2, 1),
)
ENCRYPT = list(map(ord,
    '5z]&gqtyfr$(we4{WP)H-Zn,[%\\3dL+Q;>U!pJS72FhOA1CB'
    '6v^=I_0/8|jsb9m<.TVac`uY*MK\'X~xDl}REokN:#?G"i@'
))

def rotate(n: int) -> int:
    return POW9 * (n % 3) + n // 3

def crazy(a: int, b: int) -> int:
    result = 0
    d = 1
    for _ in range(10):
        result += TABLE_CRAZY[(b // d) % 3][(a // d) % 3] * d
        d *= 3
    return result

def chinese_to_malbolge(text: str) -> str:
    # The attachment uses 94 consecutive CJK codepoints as a direct
    # substitution for printable ASCII. Mapping the smallest codepoint to '!'
    # gives a valid Malbolge program.
    base = min(map(ord, text))
    return ''.join(chr(33 + ((ord(ch) - base) % 94)) for ch in text)

def run_malbolge(source: str) -> bytes:
    mem = [0] * POW10
    i = 0
    for ch in source:
        if ch in ' \n\t\r':
            continue
        o = ord(ch)
        if not (33 <= o <= 126) or ((o + i) % 94) not in OPS_VALID:
            raise ValueError(f'invalid Malbolge character at program offset {i}: {ch!r}')
        mem[i] = o
        i += 1
    while i < POW10:
        mem[i] = crazy(mem[i - 1], mem[i - 2])
        i += 1

    a = c = d = 0
    out = bytearray()
    while True:
        if mem[c] < 33 or mem[c] > 126:
            break
        v = (mem[c] + c) % 94
        if v == 4:
            c = mem[d]
        elif v == 5:
            out.append(a % 256)
        elif v == 23:
            a = 0
        elif v == 39:
            a = mem[d] = rotate(mem[d])
        elif v == 40:
            d = mem[d]
        elif v == 62:
            a = mem[d] = crazy(a, mem[d])
        elif v == 81:
            break

        if 33 <= mem[c] <= 126:
            mem[c] = ENCRYPT[mem[c] - 33]
        c = (c + 1) % POW10
        d = (d + 1) % POW10
    return bytes(out)

def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('txt')
    text = path.read_text(encoding='utf-8')
    program = chinese_to_malbolge(text)
    output = run_malbolge(program)
    print(output.decode('utf-8'))

if __name__ == '__main__':
    main()

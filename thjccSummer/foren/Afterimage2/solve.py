#!/usr/bin/env python3
import struct
import sys
import zipfile
from pathlib import Path

KEYS = {
    0x04: ('a','A'), 0x05: ('b','B'), 0x06: ('c','C'), 0x07: ('d','D'),
    0x08: ('e','E'), 0x09: ('f','F'), 0x0a: ('g','G'), 0x0b: ('h','H'),
    0x0c: ('i','I'), 0x0d: ('j','J'), 0x0e: ('k','K'), 0x0f: ('l','L'),
    0x10: ('m','M'), 0x11: ('n','N'), 0x12: ('o','O'), 0x13: ('p','P'),
    0x14: ('q','Q'), 0x15: ('r','R'), 0x16: ('s','S'), 0x17: ('t','T'),
    0x18: ('u','U'), 0x19: ('v','V'), 0x1a: ('w','W'), 0x1b: ('x','X'),
    0x1c: ('y','Y'), 0x1d: ('z','Z'),
    0x1e: ('1','!'), 0x1f: ('2','@'), 0x20: ('3','#'), 0x21: ('4','$'),
    0x22: ('5','%'), 0x23: ('6','^'), 0x24: ('7','&'), 0x25: ('8','*'),
    0x26: ('9','('), 0x27: ('0',')'),
    0x28: ('\n','\n'), 0x2c: (' ', ' '), 0x2d: ('-','_'), 0x2e: ('=','+'),
    0x2f: ('[','{'), 0x30: (']','}'), 0x31: ('\\','|'), 0x33: (';',':'),
    0x34: ("'", '"'), 0x35: ('`','~'), 0x36: (',','<'), 0x37: ('.','>'),
    0x38: ('/','?'),
}

SHIFT_MASK = 0x22  # left shift 0x02, right shift 0x20


def read_pcap_from_zip_or_file(path: Path) -> bytes:
    data = path.read_bytes()
    if data[:4] == b'PK\x03\x04':
        with zipfile.ZipFile(path) as zf:
            names = [n for n in zf.namelist() if n.endswith('.pcap') and not n.startswith('__MACOSX/')]
            if not names:
                raise SystemExit('no .pcap found inside zip')
            return zf.read(names[0])
    return data


def iter_pcap_packets(blob: bytes):
    if len(blob) < 24:
        raise SystemExit('pcap too small')
    magic = blob[:4]
    if magic == b'\xd4\xc3\xb2\xa1':
        endian = '<'
    elif magic == b'\xa1\xb2\xc3\xd4':
        endian = '>'
    else:
        raise SystemExit('not a classic pcap')

    off = 24
    while off + 16 <= len(blob):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(endian + 'IIII', blob, off)
        off += 16
        pkt = blob[off:off + incl_len]
        off += incl_len
        yield ts_sec, ts_usec, pkt


def decode_usb_keyboard(blob: bytes) -> str:
    out = []
    prev_codes = set()

    for _ts, _usec, pkt in iter_pcap_packets(blob):
        # Linux usbmon mmap header is 64 bytes. Keyboard interrupt reports follow it.
        if len(pkt) < 72:
            continue

        report = pkt[64:72]
        mod = report[0]
        codes = [c for c in report[2:8] if c]
        current = set(codes)

        # Skip key release packets and avoid repeated held keys.
        for code in codes:
            if code in prev_codes:
                continue
            if code == 0x2a:  # backspace
                if out:
                    out.pop()
                continue
            if code not in KEYS:
                continue
            shifted = bool(mod & SHIFT_MASK)
            out.append(KEYS[code][1 if shifted else 0])

        prev_codes = current

    return ''.join(out)


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('usb_capture.pcap.zip')
    blob = read_pcap_from_zip_or_file(path)
    text = decode_usb_keyboard(blob)
    print(text)


if __name__ == '__main__':
    main()

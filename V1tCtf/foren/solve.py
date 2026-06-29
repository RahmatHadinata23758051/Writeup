#!/usr/bin/env python3
from pathlib import Path
import hashlib
import re
import struct
import subprocess
import sys
import tempfile

BASE = 0x1000  # registry hive bins start after the 4096-byte regf header
B62_ALPHABET = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def u16(b, off):
    return struct.unpack_from('<H', b, off)[0]


def u32(b, off):
    return struct.unpack_from('<I', b, off)[0]


def i32(b, off):
    return struct.unpack_from('<i', b, off)[0]


def iter_cells(hive):
    off = BASE
    while off + 0x20 <= len(hive):
        if hive[off:off + 4] != b'hbin':
            break
        hbin_size = u32(hive, off + 8)
        cur = off + 0x20
        end = off + hbin_size
        while cur + 8 <= end:
            raw_size = i32(hive, cur)
            if raw_size == 0:
                break
            size = abs(raw_size)
            if size < 8 or cur + size > end:
                break
            yield cur, size, raw_size < 0, hive[cur + 4:cur + 6]
            cur += size
        off += hbin_size


def parse_nk(hive, off):
    # cell header is at off, nk data starts at off + 4
    ft = struct.unpack_from('<Q', hive, off + 8)[0]
    value_count = u32(hive, off + 4 + 0x24)
    value_list_rel = u32(hive, off + 4 + 0x28)
    name_len = u16(hive, off + 4 + 0x48)
    name = hive[off + 4 + 0x4c:off + 4 + 0x4c + name_len]
    return ft, value_count, value_list_rel, name


def parse_vk(hive, off):
    # cell header is at off, vk data starts at off + 4
    name_len = u16(hive, off + 6)
    data_size_raw = u32(hive, off + 8)
    data_off = u32(hive, off + 12)
    data_type = u32(hive, off + 16)
    flags = u16(hive, off + 20)
    name_raw = hive[off + 24:off + 24 + name_len]
    try:
        name = name_raw.decode('latin1') if (flags & 1) else name_raw.decode('utf-16le')
    except UnicodeDecodeError:
        name = name_raw.decode('latin1', errors='replace')

    inline = bool(data_size_raw & 0x80000000)
    data_len = data_size_raw & 0x7fffffff
    if inline:
        value = struct.pack('<I', data_off)[:data_len]
        data_abs = None
    else:
        data_abs = BASE + data_off
        value = hive[data_abs + 4:data_abs + 4 + data_len]
    return {
        'name': name,
        'data_len': data_len,
        'data_abs': data_abs,
        'data_type': data_type,
        'inline': inline,
        'value': value,
    }


def sha256_counter_stream(seed, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(seed + struct.pack('<I', counter)).digest())
        counter += 1
    return bytes(out[:length])


def base62_decode(s, alphabet=B62_ALPHABET):
    n = 0
    for ch in s:
        n = n * len(alphabet) + alphabet.index(ch)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')


def find_hive(path):
    p = Path(path)
    if p.is_dir():
        hits = list(p.rglob('NTUSER.DAT'))
        if hits:
            return hits[0]
    if p.name.upper() == 'NTUSER.DAT':
        return p
    if p.suffix.lower() == '.7z':
        tmp = Path(tempfile.mkdtemp(prefix='nicetry_'))
        try:
            import py7zr  # optional convenience; system 7z also works
            with py7zr.SevenZipFile(p, 'r') as z:
                z.extractall(tmp)
        except Exception:
            subprocess.check_call(['7z', 'x', '-y', f'-o{tmp}', str(p)], stdout=subprocess.DEVNULL)
        hits = list(tmp.rglob('NTUSER.DAT'))
        if hits:
            return hits[0]
    raise FileNotFoundError('NTUSER.DAT not found. Pass NTUSER.DAT, the extracted challenge folder, or the .7z archive.')


def solve(path):
    hive_path = find_hive(path)
    hive = hive_path.read_bytes()

    # Locate the deleted key that owns the CRC32 fragments.
    deleted = None
    cells = list(iter_cells(hive))
    for off, size, inuse, sig in cells:
        if inuse or sig != b'nk':
            continue
        ft, value_count, value_list_rel, name = parse_nk(hive, off)
        if value_count == 4 and name.startswith(b'{') and name.endswith(b'}'):
            deleted = (off, ft, value_list_rel, name)
            break
    if not deleted:
        raise RuntimeError('deleted nk key with 4 values was not found')

    _, filetime, value_list_rel, _ = deleted
    value_list_abs = BASE + value_list_rel
    value_cell_offsets = []
    for i in range(4):
        rel = u32(hive, value_list_abs + 4 + i * 4)
        value_cell_offsets.append(BASE + rel)

    # Hint says physical-offset sorted CRC32 payload.
    crc_payload = b''
    for voff in sorted(value_cell_offsets):
        vk = parse_vk(hive, voff)
        crc_payload += vk['value']

    # First hidden slack blob sits in the Cfg value. Decrypt with SHA256 counter stream.
    cfg_vk_off = None
    for off, size, inuse, sig in iter_cells(hive):
        if inuse and sig == b'vk':
            vk = parse_vk(hive, off)
            if vk['name'] == 'Cfg' and vk['data_abs'] is not None:
                cfg_vk_off = off
                break
    if cfg_vk_off is None:
        raise RuntimeError('Cfg value was not found')

    cfg_vk = parse_vk(hive, cfg_vk_off)
    data_abs = cfg_vk['data_abs']
    cell_size = abs(i32(hive, data_abs))
    used = cfg_vk['data_len']
    ciphertext = hive[data_abs + 4 + used:data_abs + cell_size].rstrip(b'\x00')

    seed = struct.pack('<Q', filetime) + crc_payload
    stream = sha256_counter_stream(seed, len(ciphertext))
    stage1 = bytes(c ^ k for c, k in zip(ciphertext, stream))

    marker = b'not-the-flag-'
    if marker not in stage1:
        raise RuntimeError('stage-1 plaintext marker was not found')
    suffix = stage1.split(marker, 1)[1]

    stage2 = base62_decode(suffix)
    m = re.search(rb'[A-Za-z0-9_]+\{[^}\r\n]+\}', stage2)
    if not m:
        raise RuntimeError('flag pattern was not found in decoded payload')
    return m.group(0).decode()


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '.'
    flag = solve(target)
    print(f'<FLAG>{flag}</FLAG>')

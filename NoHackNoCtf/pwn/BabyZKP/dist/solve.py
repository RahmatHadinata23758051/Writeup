#!/usr/bin/env python3
from __future__ import annotations

import atexit
import ctypes
import itertools
import multiprocessing
import os
import random
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Iterable

ORACLE_LIMIT = 0x1337
E_BASE = 1 << 1022
STAGE1_STEP = 1 << 510
STAGE1_MASK = (1 << 512) - 1
STAGE1_MAX_ROUNDS = 150
STAGE2_SAMPLES = 4000
MT_LOW_BITS = 5
MAX_MT_CANDIDATES = 256

C_SOURCE = r'''#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#define MTN 624
#define WB 32
#define STATE_ROWS (MTN*WB)
#define NVAR 19937
#define BS 8
#define MATRIX_A 0x9908b0dfU

static inline int getbit(const uint64_t *r, int c){return (r[c>>6]>>(c&63))&1ULL;}
static inline void setbit(uint64_t *r, int c){r[c>>6]|=1ULL<<(c&63);}
static inline void xorrow(uint64_t *a,const uint64_t *b,int start,int end){for(int i=start;i<end;i++)a[i]^=b[i];}
static inline void swaprow(uint64_t *a,uint64_t *b,int n){for(int i=0;i<n;i++){uint64_t t=a[i];a[i]=b[i];b[i]=t;}}
static inline int parity_dot(const uint64_t *a,const uint64_t *b,int start,int end){unsigned p=0;for(int i=start;i<end;i++)p^=__builtin_parityll(a[i]&b[i]);return p&1;}


static uint32_t temper32(uint32_t y){y^=y>>11;y^=(y<<7)&0x9d2c5680U;y^=(y<<15)&0xefc60000U;y^=y>>18;return y;}

// mapping layout: nmap * nlabels, each value carry c in 0..2
// Returns all valid prefix/mapping candidates up to maxout.
int mt_recover(int nobs,int k,const uint32_t *zlo,const uint8_t *labels,int nlabels,
               int nmap,const uint8_t *maps,int maxout,uint32_t *out_states,uint32_t *out_pm,
               uint32_t *out_sm,int *out_map,int verbose){
    if(k<=0||k>8||nobs<=0||nlabels<1||nlabels>3||nmap<1)return -1;
    const int ncols=NVAR;
    const int aw=(ncols+63)/64;
    const int rows=nobs*k;
    const int pcount=1<<(k-1), scount=1<<k, permap=pcount*scount;
    const int totalcand=nmap*permap;
    const int rw=(totalcand+63)/64;
    const int stride=aw+rw;
    uint64_t *mat=(uint64_t*)calloc((size_t)rows*stride,sizeof(uint64_t));
    uint64_t *old=(uint64_t*)calloc((size_t)STATE_ROWS*aw,sizeof(uint64_t));
    uint64_t *newst=(uint64_t*)calloc((size_t)STATE_ROWS*aw,sizeof(uint64_t));
    if(!mat||!old||!newst){free(mat);free(old);free(newst);return -2;}
    #define DEP(st,i,b) ((st)+((size_t)(i)*32+(b))*aw)
    int vv=0;
    setbit(DEP(old,0,31),vv++);
    for(int i=1;i<MTN;i++)for(int b=0;b<32;b++)setbit(DEP(old,i,b),vv++);
    if(vv!=NVAR){free(mat);free(old);free(newst);return -9;}
    // Map the canonical 19937-bit pre-state through one twist to the valid cycle-0 state.
    memset(newst,0,(size_t)STATE_ROWS*aw*sizeof(uint64_t));
    for(int i=0;i<MTN;i++){
      int ni=(i+1)%MTN;
      for(int b=0;b<32;b++){
        uint64_t *dst=DEP(newst,i,b);
        const uint64_t *src=(i<227)?DEP(old,i+397,b):DEP(newst,i-227,b);
        memcpy(dst,src,(size_t)aw*sizeof(uint64_t));
        if(b<30)xorrow(dst,(i==MTN-1)?DEP(newst,0,b+1):DEP(old,ni,b+1),0,aw);
        else if(b==30)xorrow(dst,DEP(old,i,31),0,aw);
        if((MATRIX_A>>b)&1U)xorrow(dst,(i==MTN-1)?DEP(newst,0,0):DEP(old,ni,0),0,aw);
      }
    }
    {uint64_t *tmp=old;old=newst;newst=tmp;}
    uint32_t depmask[32]={0};
    for(int j=0;j<32;j++){uint32_t t=temper32(1U<<j);for(int b=0;b<32;b++)if((t>>b)&1U)depmask[b]|=1U<<j;}
    int oi=0; int maxpos=32*nobs; int maxcy=maxpos/624;
    clock_t t0=clock();
    for(int cy=0;cy<=maxcy;cy++){
        while(oi<nobs){int pos=32*(oi+1); if(pos/624!=cy)break; int idx=pos%624;
            for(int b=0;b<k;b++){
                uint64_t *dst=mat+(size_t)(oi*k+b)*stride;
                uint32_t dm=depmask[b];
                while(dm){int j=__builtin_ctz(dm);dm&=dm-1;xorrow(dst,DEP(old,idx,j),0,aw);}
            }
            oi++;
        }
        if(cy==maxcy)break;
        memset(newst,0,(size_t)STATE_ROWS*aw*sizeof(uint64_t));
        for(int i=0;i<MTN;i++){
            int ni=(i+1)%MTN;
            for(int b=0;b<32;b++){
                uint64_t *dst=DEP(newst,i,b);
                const uint64_t *src=(i<227)?DEP(old,i+397,b):DEP(newst,i-227,b);
                memcpy(dst,src,(size_t)aw*sizeof(uint64_t));
                if(b<30)xorrow(dst,(i==MTN-1)?DEP(newst,0,b+1):DEP(old,ni,b+1),0,aw);
                else if(b==30)xorrow(dst,DEP(old,i,31),0,aw);
                if((MATRIX_A>>b)&1U)xorrow(dst,(i==MTN-1)?DEP(newst,0,0):DEP(old,ni,0),0,aw);
            }
        }
        uint64_t *tmp=old;old=newst;newst=tmp;
        if(verbose && (cy%25==24))fprintf(stderr,"[C] symbolic cycle %d/%d %.1fs\n",cy+1,maxcy,(double)(clock()-t0)/CLOCKS_PER_SEC);
    }
    if(oi!=nobs){free(mat);free(old);free(newst);return -3;}
    // Fill all RHS candidate columns.
    uint32_t kmask=(1U<<k)-1U;
    for(int i=0;i<nobs;i++){
        uint32_t z=zlo[i]&kmask; int lab=labels[i];
        for(int mi=0;mi<nmap;mi++){
            int c=maps[mi*nlabels+lab];
            int base=mi*permap;
            for(int pi=0;pi<pcount;pi++){
                uint32_t p=((uint32_t)pi<<1)|1U;
                int b2=base+pi*scount;
                for(int s=0;s<scount;s++){
                    uint32_t r=(z-(uint32_t)s+(uint32_t)c*p)&kmask;
                    int cand=b2+s;
                    for(int bit=0;bit<k;bit++)if((r>>bit)&1U){uint64_t *row=mat+(size_t)(i*k+bit)*stride;row[aw+(cand>>6)]|=1ULL<<(cand&63);}
                }
            }
        }
    }
    free(old);free(newst);
    if(verbose)fprintf(stderr,"[C] matrix %dx%d + %d candidates, %.1f MiB\n",rows,ncols,totalcand,(double)((size_t)rows*stride*8)/(1024*1024));
    int *pivcols=(int*)malloc((size_t)ncols*sizeof(int));
    uint64_t *table=(uint64_t*)malloc((size_t)(1<<BS)*stride*sizeof(uint64_t));
    if(!pivcols||!table){free(mat);free(pivcols);free(table);return -4;}
    int rank=0,col=0,blockno=0;
    while(col<ncols && rank<rows){
        int bend=col+BS; if(bend>ncols)bend=ncols;
        int r=0; int bpiv[BS]; uint64_t bpat[BS];
        // Find independent rows based on bits in this column block.
        for(int scan=rank;scan<rows && r<(bend-col);scan++){
            uint64_t *sr=mat+(size_t)scan*stride;
            uint64_t pat=0;for(int q=0;q<bend-col;q++)if(getbit(sr,col+q))pat|=1ULL<<q;
            uint64_t red=pat, comb=0;
            for(int j=0;j<r;j++)if((red>>bpiv[j])&1ULL){red^=bpat[j];comb^=1ULL<<j;}
            if(!red)continue;
            if(scan!=rank+r)swaprow(sr,mat+(size_t)(rank+r)*stride,stride);
            uint64_t *nr=mat+(size_t)(rank+r)*stride;
            for(int j=0;j<r;j++)if((comb>>j)&1ULL)xorrow(nr,mat+(size_t)(rank+j)*stride,col>>6,stride);
            int pb=__builtin_ctzll(red);
            // Eliminate new pivot from existing block pivot rows.
            for(int j=0;j<r;j++)if((bpat[j]>>pb)&1ULL){
                xorrow(mat+(size_t)(rank+j)*stride,nr,col>>6,stride);
                bpat[j]^=red;
            }
            bpiv[r]=pb;bpat[r]=red;pivcols[rank+r]=col+pb;r++;
        }
        if(r==0){col=bend;continue;}
        int startw=col>>6, tail=stride-startw, tabs=1<<r;
        memset(table,0,(size_t)tabs*tail*sizeof(uint64_t));
        for(int mask=1;mask<tabs;mask++){
            int bit=__builtin_ctz(mask),prev=mask&(mask-1);
            uint64_t *dst=table+(size_t)mask*tail;
            uint64_t *prv=table+(size_t)prev*tail;
            uint64_t *pv=mat+(size_t)(rank+bit)*stride+startw;
            for(int w=0;w<tail;w++)dst[w]=prv[w]^pv[w];
        }
        for(int rr=rank+r;rr<rows;rr++){
            uint64_t *row=mat+(size_t)rr*stride;int mask=0;
            for(int j=0;j<r;j++)if(getbit(row,col+bpiv[j]))mask|=1<<j;
            if(mask){uint64_t *tv=table+(size_t)mask*tail;for(int w=0;w<tail;w++)row[startw+w]^=tv[w];}
        }
        rank+=r;col=bend;blockno++;
        if(verbose && blockno%200==0)fprintf(stderr,"[C] elim rank %d/%d col %d %.1fs\n",rank,ncols,col,(double)(clock()-t0)/CLOCKS_PER_SEC);
    }
    if(verbose)fprintf(stderr,"[C] elimination rank=%d rows=%d %.1fs\n",rank,rows,(double)(clock()-t0)/CLOCKS_PER_SEC);
    if(rank<ncols){free(mat);free(pivcols);free(table);return -5;}
    uint64_t *valid=(uint64_t*)malloc((size_t)rw*sizeof(uint64_t));
    for(int w=0;w<rw;w++)valid[w]=~0ULL;
    if(totalcand&63)valid[rw-1]&=(1ULL<<(totalcand&63))-1ULL;
    for(int rr=rank;rr<rows;rr++){
        uint64_t *row=mat+(size_t)rr*stride+aw;
        for(int w=0;w<rw;w++)valid[w]&=~row[w];
    }
    int found=0;
    for(int w=0;w<rw;w++){uint64_t v=valid[w];while(v){int b=__builtin_ctzll(v);int chosen=w*64+b;if(chosen<totalcand){
        if(found<maxout){
          uint64_t *x=(uint64_t*)calloc((size_t)aw,sizeof(uint64_t));
          for(int ii=rank-1;ii>=0;ii--){int pc=pivcols[ii];uint64_t *row=mat+(size_t)ii*stride;int rhs=(row[aw+(chosen>>6)]>>(chosen&63))&1ULL;
            int sw=pc>>6;uint64_t mask=(pc&63)==63?0:~((1ULL<<((pc&63)+1))-1ULL);unsigned par=__builtin_parityll((row[sw]&mask)&x[sw]);
            for(int ww=sw+1;ww<aw;ww++)par^=__builtin_parityll(row[ww]&x[ww]);
            if(rhs^(par&1))setbit(x,pc);
          }
          uint32_t *out_state=out_states+(size_t)found*MTN;
          uint32_t pre[MTN]; memset(pre,0,sizeof(pre)); int vi=0;
          if(getbit(x,vi++))pre[0]|=1U<<31;
          for(int ii=1;ii<MTN;ii++)for(int bb=0;bb<32;bb++)if(getbit(x,vi++))pre[ii]|=1U<<bb;
          for(int ii=0;ii<MTN;ii++){uint32_t nx=(pre[ii]&0x80000000U)|(((ii==MTN-1)?out_state[0]:pre[ii+1])&0x7fffffffU);uint32_t src=(ii<227)?pre[ii+397]:out_state[ii-227];out_state[ii]=src^(nx>>1)^((nx&1U)?MATRIX_A:0U);}
          int mi=chosen/permap, local=chosen%permap, pi=local/scount, ss=local%scount;
          out_pm[found]=((uint32_t)pi<<1)|1U;out_sm[found]=(uint32_t)ss;out_map[found]=mi;
          free(x);
        }
        found++;
      }v&=v-1;}}
    if(verbose)fprintf(stderr,"[C] valid candidate pairs=%d (returned %d)\n",found,found<maxout?found:maxout);
    free(valid);free(mat);free(pivcols);free(table);
    return found;
}
'''


_CLUSTER_P = 0
_CLUSTER_INV2 = 0


def _init_cluster_worker(p: int, inv2: int) -> None:
    global _CLUSTER_P, _CLUSTER_INV2
    _CLUSTER_P = p
    _CLUSTER_INV2 = inv2


def _cluster_key_worker(record: tuple[int, int]) -> int:
    a, z = record
    return a * pow(_CLUSTER_INV2, z, _CLUSTER_P) % _CLUSTER_P


def compute_cluster_labels(records: list[tuple[int, int]], p: int) -> tuple[list[int], int]:
    inv2 = pow(2, -1, p)
    workers = min(4, os.cpu_count() or 1)
    keys: list[int]
    if workers > 1 and len(records) >= 512 and sys.platform != "win32":
        try:
            ctx = multiprocessing.get_context("fork")
            with ctx.Pool(
                processes=workers,
                initializer=_init_cluster_worker,
                initargs=(p, inv2),
            ) as pool:
                keys = pool.map(_cluster_key_worker, records, chunksize=32)
        except (OSError, RuntimeError):
            _init_cluster_worker(p, inv2)
            keys = [_cluster_key_worker(record) for record in records]
    else:
        _init_cluster_worker(p, inv2)
        keys = [_cluster_key_worker(record) for record in records]

    cluster_to_label: dict[int, int] = {}
    labels: list[int] = []
    for key in keys:
        label = cluster_to_label.setdefault(key, len(cluster_to_label))
        labels.append(label)
        if len(cluster_to_label) > 3:
            raise RuntimeError("jumlah carry cluster lebih dari tiga; parsing atau asumsi rusak")
    return labels, len(cluster_to_label)


class Tube:
    def __init__(self, host: str, port: int, timeout: float = 180.0) -> None:
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(timeout)
        self.buf = bytearray()

    def recv_until(self, marker: bytes) -> bytes:
        while True:
            idx = self.buf.find(marker)
            if idx >= 0:
                end = idx + len(marker)
                out = bytes(self.buf[:end])
                del self.buf[:end]
                return out
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError(bytes(self.buf).decode(errors="replace"))
            self.buf.extend(chunk)

    def sendline(self, value: str | int | bytes) -> None:
        if isinstance(value, bytes):
            data = value
        else:
            data = str(value).encode()
        self.sock.sendall(data + b"\n")

    def recv_all(self, timeout: float = 8.0) -> bytes:
        chunks = [bytes(self.buf)]
        self.buf.clear()
        self.sock.settimeout(timeout)
        while True:
            try:
                part = self.sock.recv(65536)
            except socket.timeout:
                break
            if not part:
                break
            chunks.append(part)
        return b"".join(chunks)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def parse_last_int(blob: bytes, name: bytes) -> int:
    matches = re.findall(rb"(?:^|\n)" + re.escape(name) + rb"=(\d+)", blob)
    if not matches:
        raise ValueError(f"field {name.decode()} tidak ditemukan di output:\n{blob.decode(errors='replace')}")
    return int(matches[-1])


def ceil_div(a: int, b: int) -> int:
    return -((-a) // b)


def recover_stage1(records: list[tuple[int, int]], p: int) -> int | None:
    lo, hi = 0, STAGE1_MASK
    checks: list[tuple[int, int]] = []
    for i in range(1, len(records)):
        a0, z0 = records[i - 1]
        a1, z1 = records[i]
        dz = z1 - z0
        if dz <= 0:
            continue
        lo = max(lo, ceil_div(dz - STAGE1_MASK, STAGE1_STEP))
        hi = min(hi, (dz + STAGE1_MASK) // STAGE1_STEP)
        ratio = a1 * pow(a0, -1, p) % p
        checks.append((dz, ratio))

    if len(checks) < 2 or lo > hi or hi - lo > 128:
        return None

    valid: list[int] = []
    for candidate in range(max(0, lo), min(STAGE1_MASK, hi) + 1):
        if all(pow(2, dz - STAGE1_STEP * candidate, p) == ratio for dz, ratio in checks):
            valid.append(candidate)
    return valid[0] if len(valid) == 1 else None


def compile_helper() -> tuple[ctypes.CDLL, Path]:
    workdir = Path.cwd()
    so_path = workdir / f".babyzkp_mtrecover_{os.getpid()}.so"
    commands = [
        ["gcc", "-O3", "-march=native", "-shared", "-fPIC", "-x", "c", "-o", str(so_path), "-"],
        ["gcc", "-O3", "-shared", "-fPIC", "-x", "c", "-o", str(so_path), "-"],
    ]
    last_error = ""
    for command in commands:
        result = subprocess.run(command, input=C_SOURCE.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            break
        last_error = result.stderr.decode(errors="replace")
    else:
        raise RuntimeError(f"gagal mengompilasi helper C:\n{last_error}")

    def cleanup() -> None:
        try:
            so_path.unlink()
        except FileNotFoundError:
            pass

    atexit.register(cleanup)
    lib = ctypes.CDLL(str(so_path))
    lib.mt_recover.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_int,
    ]
    lib.mt_recover.restype = ctypes.c_int
    return lib, so_path


def recover_mt_states(
    lib: ctypes.CDLL,
    z_values: list[int],
    labels: list[int],
    label_count: int,
) -> list[tuple[tuple[int, ...], int, int, tuple[int, ...]]]:
    mappings = list(itertools.permutations(range(3), label_count))
    flat_mappings = [value for mapping in mappings for value in mapping]
    n = len(z_values)

    z_array = (ctypes.c_uint32 * n)(*(z & 0xFFFFFFFF for z in z_values))
    label_array = (ctypes.c_uint8 * n)(*labels)
    mapping_array = (ctypes.c_uint8 * len(flat_mappings))(*flat_mappings)
    states_array = (ctypes.c_uint32 * (MAX_MT_CANDIDATES * 624))()
    p_array = (ctypes.c_uint32 * MAX_MT_CANDIDATES)()
    s_array = (ctypes.c_uint32 * MAX_MT_CANDIDATES)()
    map_array = (ctypes.c_int * MAX_MT_CANDIDATES)()

    found = lib.mt_recover(
        n,
        MT_LOW_BITS,
        z_array,
        label_array,
        label_count,
        len(mappings),
        mapping_array,
        MAX_MT_CANDIDATES,
        states_array,
        p_array,
        s_array,
        map_array,
        1,
    )
    if found < 0:
        raise RuntimeError(f"helper MT gagal dengan kode {found}")
    if found == 0:
        raise RuntimeError("tidak ada state MT yang konsisten")

    result: list[tuple[tuple[int, ...], int, int, tuple[int, ...]]] = []
    returned = min(found, MAX_MT_CANDIDATES)
    for i in range(returned):
        state = tuple(int(x) for x in states_array[i * 624 : (i + 1) * 624])
        result.append((state, int(p_array[i]), int(s_array[i]), mappings[int(map_array[i])]))
    return result


def select_mt_secret(
    candidates: Iterable[tuple[tuple[int, ...], int, int, tuple[int, ...]]],
    p: int,
    records: list[tuple[int, int]],
) -> int:
    seen_states: set[tuple[int, ...]] = set()
    for state, p_low, s_low, mapping in candidates:
        if state in seen_states:
            continue
        seen_states.add(state)
        clone = random.Random()
        clone.setstate((3, state + (0,), None))
        w = clone.getrandbits(1024)
        ok = True
        for a, _z in records[:12]:
            r = clone.getrandbits(1024)
            if pow(2, r, p) != a:
                ok = False
                break
        if ok:
            print(f"[+] MT state valid, low(pp)={p_low:#x}, low(s)={s_low:#x}, mapping={mapping}")
            return w
    raise RuntimeError("semua kandidat state MT gagal divalidasi terhadap commitment")


def solve(host: str, port: int) -> str:
    print("[*] compiling GF(2) recovery helper")
    lib, _ = compile_helper()
    tube = Tube(host, port)
    total_queries = 0
    try:
        # Stage 1
        block = tube.recv_until(b"e=")
        p1 = parse_last_int(block, b"p")
        records1: list[tuple[int, int]] = []
        w1: int | None = None
        for round_index in range(STAGE1_MAX_ROUNDS):
            a = parse_last_int(block, b"a")
            e = E_BASE + round_index * STAGE1_STEP
            if e > p1 - 2:
                raise RuntimeError("challenge e Stage 1 melewati batas p-2")
            tube.sendline(e)
            response = tube.recv_until(b"verifier accept? (Y/N)")
            z = parse_last_int(response, b"z")
            records1.append((a, z))
            total_queries += 1
            w1 = recover_stage1(records1, p1)
            if w1 is not None:
                print(f"[+] Stage 1 recovered after {len(records1)} rounds")
                tube.sendline("Y")
                tube.recv_until(b"w=")
                tube.sendline(w1)
                break
            tube.sendline("N")
            block = tube.recv_until(b"e=")
        else:
            raise RuntimeError("Stage 1 belum pulih sebelum batas lokal")

        # Stage 2
        block = tube.recv_until(b"e=")
        p2 = parse_last_int(block, b"p")
        records2: list[tuple[int, int]] = []
        z_values: list[int] = []

        if total_queries + STAGE2_SAMPLES >= ORACLE_LIMIT:
            raise RuntimeError("jumlah query lokal melewati ORACLE_LIMIT")

        for i in range(STAGE2_SAMPLES):
            a = parse_last_int(block, b"a")
            tube.sendline(E_BASE)
            response = tube.recv_until(b"verifier accept? (Y/N)")
            z = parse_last_int(response, b"z")
            records2.append((a, z))
            z_values.append(z)

            total_queries += 1
            if (i + 1) % 250 == 0:
                print(f"[*] Stage 2 samples: {i + 1}/{STAGE2_SAMPLES}")

            if i + 1 < STAGE2_SAMPLES:
                tube.sendline("N")
                block = tube.recv_until(b"e=")

        print("[*] grouping Stage 2 carry classes")
        labels, label_count = compute_cluster_labels(records2, p2)
        print(f"[+] Stage 2 carry clusters: {label_count}")
        print(f"[*] recovering MT19937 from {STAGE2_SAMPLES} responses")
        mt_candidates = recover_mt_states(lib, z_values, labels, label_count)
        w2 = select_mt_secret(mt_candidates, p2, records2)

        tube.sendline("Y")
        tube.recv_until(b"w=")
        tube.sendline(w2)
        output = tube.recv_all()
        text = output.decode(errors="replace")
        print(text, end="" if text.endswith("\n") else "\n")
        match = re.search(r"NHNC\{[^}\r\n]+\}", text)
        if not match:
            raise RuntimeError("service selesai tetapi flag NHNC{...} tidak ditemukan")
        flag = match.group(0)
        print(f"<FLAG>{flag}</FLAG>")
        return flag
    finally:
        tube.close()


def main() -> None:
    if len(sys.argv) not in (2, 3):
        print(f"usage: {sys.argv[0]} HOST [PORT]", file=sys.stderr)
        print(f"example: {sys.argv[0]} chal.whale-tw.com 51337", file=sys.stderr)
        raise SystemExit(2)
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) == 3 else 51337
    try:
        solve(host, port)
    except (OSError, EOFError, ValueError, RuntimeError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()

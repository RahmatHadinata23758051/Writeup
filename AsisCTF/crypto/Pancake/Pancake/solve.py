#!/usr/bin/env python3
import argparse, json, os, re, shutil, subprocess, tempfile, textwrap
from hashlib import sha256
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SEED_C = r'''
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#define MAX_THREADS 128
static uint32_t target[8]; static atomic_int found=0; static atomic_uint found_seed=0;
static const uint32_t K[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static inline uint32_t R(uint32_t x,int n){return (x>>n)|(x<<(32-n));} static inline uint32_t Ch(uint32_t x,uint32_t y,uint32_t z){return (x&y)^((~x)&z);} static inline uint32_t Maj(uint32_t x,uint32_t y,uint32_t z){return (x&y)^(x&z)^(y&z);} static inline uint32_t S0(uint32_t x){return R(x,2)^R(x,13)^R(x,22);} static inline uint32_t S1(uint32_t x){return R(x,6)^R(x,11)^R(x,25);} static inline uint32_t s0(uint32_t x){return R(x,7)^R(x,18)^(x>>3);} static inline uint32_t s1(uint32_t x){return R(x,17)^R(x,19)^(x>>10);} 
static inline int check(uint32_t seed){uint32_t w[64]; w[0]=0x4b312d53u; w[1]=0x4545442du; w[2]=0x48494e54u; w[3]=seed; w[4]=0x80000000u; for(int i=5;i<15;i++)w[i]=0; w[15]=128u; for(int i=16;i<64;i++)w[i]=s1(w[i-2])+w[i-7]+s0(w[i-15])+w[i-16]; uint32_t a=0x6a09e667,b=0xbb67ae85,c=0x3c6ef372,d=0xa54ff53a,e=0x510e527f,f=0x9b05688c,g=0x1f83d9ab,h=0x5be0cd19; for(int i=0;i<64;i++){uint32_t T1=h+S1(e)+Ch(e,f,g)+K[i]+w[i],T2=S0(a)+Maj(a,b,c); h=g;g=f;f=e;e=d+T1;d=c;c=b;b=a;a=T1+T2;} uint32_t dg[8]={a+0x6a09e667,b+0xbb67ae85,c+0x3c6ef372,d+0xa54ff53a,e+0x510e527f,f+0x9b05688c,g+0x1f83d9ab,h+0x5be0cd19}; return !memcmp(dg,target,32);} 
int hx(char c){return c<='9'?c-'0':(c|32)-'a'+10;} void parse(const char*h){for(int i=0;i<8;i++){uint32_t x=0;for(int j=0;j<8;j++)x=(x<<4)|hx(h[i*8+j]);target[i]=x;}}
typedef struct{uint64_t s,e;} A; void* worker(void*vp){A*a=(A*)vp; for(uint64_t x=a->s;x<a->e && !atomic_load(&found);x++){ if(check((uint32_t)x)){atomic_store(&found_seed,(uint32_t)x);atomic_store(&found,1);break;}} return NULL;}
int main(int ac,char**av){if(ac<3)return 1; parse(av[1]); int nt=atoi(av[2]); if(nt<1)nt=1; if(nt>MAX_THREADS)nt=MAX_THREADS; pthread_t th[MAX_THREADS]; A ar[MAX_THREADS]; uint64_t total=1ULL<<32, chunk=(total+nt-1)/nt; for(int i=0;i<nt;i++){ar[i].s=i*chunk; ar[i].e=(i+1)*chunk; if(ar[i].e>total)ar[i].e=total; pthread_create(&th[i],0,worker,&ar[i]);} for(int i=0;i<nt;i++)pthread_join(th[i],0); if(found){printf("%u\n",found_seed);return 0;} return 2;}
'''

ALT_C = r'''
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <openssl/evp.h>
#define MAX_THREADS 128
#define BATCH 32768
static uint8_t key[32],base[16],exclude[16],result[16]; static atomic_int found=0;
int hx(char c){return c<='9'?c-'0':(c|32)-'a'+10;} void h2b(const char*h,uint8_t*o,int n){for(int i=0;i<n;i++)o[i]=(hx(h[2*i])<<4)|hx(h[2*i+1]);}
typedef struct{uint64_t s,e;} A;
void* worker(void*vp){A*a=(A*)vp; EVP_CIPHER_CTX*ctx=EVP_CIPHER_CTX_new(); EVP_DecryptInit_ex(ctx,EVP_aes_256_ecb(),0,key,0); EVP_CIPHER_CTX_set_padding(ctx,0); uint8_t*in=aligned_alloc(64,BATCH*16),*out=aligned_alloc(64,BATCH*16+32); for(int i=0;i<BATCH;i++)memcpy(in+i*16,base,12); for(uint64_t cur=a->s;cur<a->e && !atomic_load(&found);){uint32_t cnt=(a->e-cur>BATCH)?BATCH:(uint32_t)(a->e-cur); for(uint32_t i=0;i<cnt;i++){uint32_t v=(uint32_t)(cur+i); in[i*16+12]=v>>24; in[i*16+13]=v>>16; in[i*16+14]=v>>8; in[i*16+15]=v;} int l1=0,l2=0; EVP_DecryptInit_ex(ctx,0,0,0,0); EVP_DecryptUpdate(ctx,out,&l1,in,cnt*16); EVP_DecryptFinal_ex(ctx,out+l1,&l2); for(uint32_t i=0;i<cnt;i++){uint8_t*b=out+i*16; if(!b[12]&&!b[13]&&!b[14]&&!b[15]&&memcmp(b,exclude,16)){if(!atomic_exchange(&found,1))memcpy(result,b,16); goto done;}} cur+=cnt;} done: free(in);free(out);EVP_CIPHER_CTX_free(ctx);return 0;}
int main(int ac,char**av){if(ac<5)return 1; h2b(av[1],key,32);h2b(av[2],base,16);h2b(av[4],exclude,16); int nt=atoi(av[3]); if(nt<1)nt=1;if(nt>MAX_THREADS)nt=MAX_THREADS; pthread_t th[MAX_THREADS]; A ar[MAX_THREADS]; uint64_t total=1ULL<<32,chunk=(total+nt-1)/nt; for(int i=0;i<nt;i++){ar[i].s=i*chunk;ar[i].e=(i+1)*chunk;if(ar[i].e>total)ar[i].e=total;pthread_create(&th[i],0,worker,&ar[i]);} for(int i=0;i<nt;i++)pthread_join(th[i],0); if(found){for(int i=0;i<16;i++)printf("%02x",result[i]);puts("");return 0;} return 2;}
'''

def compile_c(src: str, name: str, extra=()):
    cc = shutil.which("gcc") or shutil.which("clang")
    if not cc:
        raise SystemExit("gcc/clang tidak ditemukan")
    td = tempfile.mkdtemp(prefix="pancake_")
    c = Path(td, name + ".c"); b = Path(td, name)
    c.write_text(src)
    cmd = [cc, "-O3", "-march=native", str(c), "-o", str(b), "-lpthread", *extra]
    subprocess.check_call(cmd)
    return str(b)

def load_challenge(path: str):
    s = Path(path).read_text(errors="ignore").strip()
    if s.startswith("{"):
        return json.loads(s)
    for line in s.splitlines():
        line = line.strip()
        if line.startswith('{"d"'):
            return json.loads(line.split('%')[0].strip())
    m = re.search(r'\{"d"\s*:\s*\d+.*\}', s)
    if not m:
        raise SystemExit("challenge JSON tidak ditemukan")
    return json.loads(m.group(0))

def aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("challenge", help="challenge.json atau paste terminal yang berisi JSON")
    ap.add_argument("--threads", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--seed", type=int, help="opsional, isi kalau sudah tahu seed agar tidak brute force")
    args = ap.parse_args()

    ch = load_challenge(args.challenge)
    d = int(ch["d"]); nonce_bits = 128 - d; mask = (1 << nonce_bits) - 1
    bw = (nonce_bits + 7) // 8
    dec = lambda h: int.from_bytes(bytes.fromhex(h), "big") & mask
    encn = lambda x: (x & mask).to_bytes(bw, "big").hex()
    n1, n2 = dec(ch["n"][0]), dec(ch["n"][1])

    seed = args.seed
    if seed is None:
        seed_bin = compile_c(SEED_C, "seed")
        seed = int(subprocess.check_output([seed_bin, ch["a"], str(args.threads)], text=True).strip())
    k1 = sha256(b"K1-SEED" + seed.to_bytes(4, "big")).digest()

    block_n2 = (((n2 & mask) << d)).to_bytes(16, "big")
    target = int.from_bytes(aes_ecb_encrypt(k1, block_n2), "big") >> d
    base = (target << d).to_bytes(16, "big")
    exclude = (((n2 & mask) << d)).to_bytes(16, "big")

    alt_bin = compile_c(ALT_C, "alt", ["-lcrypto"])
    alt_block = bytes.fromhex(subprocess.check_output([alt_bin, k1.hex(), base.hex(), str(args.threads), exclude.hex()], text=True).strip())
    alt = int.from_bytes(alt_block, "big") >> d

    ticket_key = sha256(b"SEALED-TICKET-KEY" + k1 + n1.to_bytes(bw, "big") + alt.to_bytes(bw, "big")).digest()[:16]
    ticket_nonce = sha256(b"SEALED-TICKET-IV" + ticket_key).digest()[:12]
    ticket = AESGCM(ticket_key).decrypt(ticket_nonce, bytes.fromhex(ch["z"]["c"]) + bytes.fromhex(ch["z"]["t"]), None)
    rec = json.loads(ticket)

    sample_c = bytes.fromhex(rec["x"]["c"])
    flag_c = bytes.fromhex(ch["y"]["c"])
    flag = bytes(a ^ b for a, b in zip(flag_c, sample_c)).decode(errors="replace")

    print(f"seed = {seed}")
    print(f"alt  = {encn(alt)}")
    print(f"flag = {flag}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import os
import struct
import subprocess
import sys
from pathlib import Path

# lumaes stores a white-box AES instance in .data.  The code body is heavily
# obfuscated/encrypted, but the useful tables are enough to invert encryption.
# Model recovered from tracing the decrypted AArch64 body:
#   - 9 rounds
#   - ShiftRows permutation before each round
#   - TII -> xor128 -> TIII -> xor128 per column
#   - 32-bit intermediate/result are consumed big-endian
#   - final TV layer also receives ShiftRows-permuted state

SR_VA      = 0xB701A0
WB_TII_VA  = 0xB70204
WB_TIII_VA = 0xB94204
WB_XOR_VA  = 0xBB8204
WB_TV_VA   = 0xC24204
FLAG_CT_VA = 0xC25208

SIZES = {
    "sr": 16,
    "flag_ct": 64,
    "tii": 0x24000,     # 9 * 16 * 256 * 4
    "tiii": 0x24000,
    "xor": 0x6C000,     # 9 * 8 xor128 * 3 xor32 * 0x800
    "tv": 0x1000,       # 16 * 256
}

C_HELPER = r'''
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint8_t sr[16], invsr[16], flag_ct[64], tv[16][256], wxor[216][2048];
static uint32_t tii[9][16][256], tiii[9][16][256];
static int perm_sr[16];

static uint32_t xor32_idx(int idx, uint32_t a, uint32_t b){
    uint8_t *tab = wxor[idx];
    uint32_t r = 0;
    for(int k=0;k<8;k++){
        int sh = 28 - 4*k;
        int id = (((a >> sh) & 15) << 4) | ((b >> sh) & 15);
        r |= ((uint32_t)tab[k*256 + id]) << sh;
    }
    return r;
}

static int inv_left(int idx, uint32_t right, uint32_t target, uint32_t *out){
    uint8_t *tab = wxor[idx];
    uint32_t res = 0;
    for(int k=0;k<8;k++){
        int sh = 28 - 4*k;
        int rn = (right >> sh) & 15;
        int tn = (target >> sh) & 15;
        int found = -1;
        for(int ln=0; ln<16; ln++){
            if(tab[k*256 + (ln << 4) + rn] == tn){
                if(found != -1) return 0;
                found = ln;
            }
        }
        if(found < 0) return 0;
        res |= ((uint32_t)found) << sh;
    }
    *out = res;
    return 1;
}

#define HSIZE 131072
static uint32_t hkeys[HSIZE];
static uint16_t hvals[HSIZE];
static uint8_t hused[HSIZE];

static uint32_t hash32(uint32_t x){
    x ^= x >> 16; x *= 0x7feb352dU;
    x ^= x >> 15; x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
}
static void hclear(void){ memset(hused, 0, sizeof(hused)); }
static void hput(uint32_t key, uint16_t val){
    uint32_t h = hash32(key) & (HSIZE - 1);
    while(hused[h]){
        if(hkeys[h] == key){ hvals[h] = val; return; }
        h = (h + 1) & (HSIZE - 1);
    }
    hused[h] = 1; hkeys[h] = key; hvals[h] = val;
}
static int hget(uint32_t key, uint16_t *val){
    uint32_t h = hash32(key) & (HSIZE - 1);
    while(hused[h]){
        if(hkeys[h] == key){ *val = hvals[h]; return 1; }
        h = (h + 1) & (HSIZE - 1);
    }
    return 0;
}

static uint32_t (*table_ptr(int tid))[16][256]{ return tid == 0 ? tii : tiii; }

static int inv_x128(int tid, int r, int pos[4], int idx, uint32_t target, uint8_t out[4]){
    uint32_t (*tab)[16][256] = table_ptr(tid);
    hclear();
    for(int b0=0; b0<256; b0++){
        uint32_t w0 = tab[r][pos[0]][b0];
        for(int b1=0; b1<256; b1++){
            uint32_t L = xor32_idx(idx, w0, tab[r][pos[1]][b1]);
            hput(L, (uint16_t)((b0 << 8) | b1));
        }
    }
    for(int b2=0; b2<256; b2++){
        uint32_t w2 = tab[r][pos[2]][b2];
        for(int b3=0; b3<256; b3++){
            uint32_t R = xor32_idx(idx + 1, w2, tab[r][pos[3]][b3]);
            uint32_t need;
            uint16_t v;
            if(inv_left(idx + 2, R, target, &need) && hget(need, &v)){
                out[0] = v >> 8;
                out[1] = v & 255;
                out[2] = b2;
                out[3] = b3;
                return 1;
            }
        }
    }
    return 0;
}

static int comp_inv(int r, int c, uint8_t outbs[4], uint8_t inbs[4]){
    int pos[4] = {4*c, 4*c+1, 4*c+2, 4*c+3};
    int idx = 3 * (8*r + 2*c);
    uint32_t target = ((uint32_t)outbs[0] << 24) | ((uint32_t)outbs[1] << 16) |
                      ((uint32_t)outbs[2] << 8)  |  (uint32_t)outbs[3];
    uint8_t mid[4];
    if(!inv_x128(1, r, pos, idx + 3, target, mid)) return 0;
    uint32_t w1 = ((uint32_t)mid[0] << 24) | ((uint32_t)mid[1] << 16) |
                  ((uint32_t)mid[2] << 8)  |  (uint32_t)mid[3];
    return inv_x128(0, r, pos, idx, w1, inbs);
}

static uint32_t fwd_x128(int tid, int r, int pos[4], int idx, uint8_t bs[4]){
    uint32_t (*tab)[16][256] = table_ptr(tid);
    uint32_t w0 = tab[r][pos[0]][bs[0]];
    uint32_t w1 = tab[r][pos[1]][bs[1]];
    uint32_t w2 = tab[r][pos[2]][bs[2]];
    uint32_t w3 = tab[r][pos[3]][bs[3]];
    return xor32_idx(idx + 2, xor32_idx(idx, w0, w1), xor32_idx(idx + 1, w2, w3));
}

static void comp_fwd(int r, int c, uint8_t inbs[4], uint8_t outbs[4]){
    int pos[4] = {4*c, 4*c+1, 4*c+2, 4*c+3};
    int idx = 3 * (8*r + 2*c);
    uint32_t w1 = fwd_x128(0, r, pos, idx, inbs);
    uint8_t mid[4] = { (uint8_t)(w1 >> 24), (uint8_t)(w1 >> 16),
                       (uint8_t)(w1 >> 8),  (uint8_t)w1 };
    uint32_t w2 = fwd_x128(1, r, pos, idx + 3, mid);
    outbs[0] = w2 >> 24; outbs[1] = w2 >> 16; outbs[2] = w2 >> 8; outbs[3] = w2;
}

static void apply_sr(uint8_t in[16], uint8_t out[16]){
    for(int i=0; i<16; i++) out[i] = in[perm_sr[i]];
}
static void unapply_sr(uint8_t in[16], uint8_t out[16]){
    for(int i=0; i<16; i++) out[perm_sr[i]] = in[i];
}

static int inv_tv(uint8_t ct[16], uint8_t st[16]){
    for(int i=0; i<16; i++){
        int found = -1;
        for(int b=0; b<256; b++){
            if(tv[i][b] == ct[i]){
                if(found != -1) return 0;
                found = b;
            }
        }
        if(found < 0) return 0;
        st[perm_sr[i]] = found;
    }
    return 1;
}

static void fwd_tv(uint8_t st[16], uint8_t ct[16]){
    for(int i=0; i<16; i++) ct[i] = tv[i][st[perm_sr[i]]];
}

static int inv_block(uint8_t ct[16], uint8_t pt[16]){
    uint8_t st[16], pin[16], prev[16], out4[4];
    if(!inv_tv(ct, st)) return 0;
    for(int r=8; r>=0; r--){
        for(int c=0; c<4; c++){
            if(!comp_inv(r, c, st + 4*c, out4)) return 0;
            memcpy(pin + 4*c, out4, 4);
        }
        unapply_sr(pin, prev);
        memcpy(st, prev, 16);
    }
    memcpy(pt, st, 16);
    return 1;
}

static void fwd_block(uint8_t pt[16], uint8_t ct[16]){
    uint8_t st[16], pin[16], out[16], out4[4];
    memcpy(st, pt, 16);
    for(int r=0; r<9; r++){
        apply_sr(st, pin);
        for(int c=0; c<4; c++){
            comp_fwd(r, c, pin + 4*c, out4);
            memcpy(out + 4*c, out4, 4);
        }
        memcpy(st, out, 16);
    }
    fwd_tv(st, ct);
}

int main(int argc, char **argv){
    if(argc != 2) return 2;
    FILE *f = fopen(argv[1], "rb");
    if(!f) return 3;
    fread(sr, 1, 16, f);
    fread(flag_ct, 1, 64, f);
    fread(tii, 1, 0x24000, f);
    fread(tiii, 1, 0x24000, f);
    fread(wxor, 1, 0x6c000, f);
    fread(tv, 1, 0x1000, f);
    fclose(f);

    for(int i=0; i<16; i++){ invsr[sr[i]] = i; perm_sr[i] = sr[i]; }

    uint8_t pt[64], check[16];
    for(int bi=0; bi<4; bi++){
        if(!inv_block(flag_ct + 16*bi, pt + 16*bi)) return 4;
        fwd_block(pt + 16*bi, check);
        if(memcmp(check, flag_ct + 16*bi, 16) != 0) return 5;
    }

    int n = 64;
    int pad = pt[63];
    if(pad > 0 && pad <= 16){
        int ok = 1;
        for(int i=0; i<pad; i++) if(pt[63-i] != pad) ok = 0;
        if(ok) n -= pad;
    }
    fwrite(pt, 1, n, stdout);
    fputc('\n', stdout);
    return 0;
}
'''

def load_elf(path: Path):
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("ELF harus 64-bit little-endian")
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize = struct.unpack_from("<H", data, 54)[0]
    e_phnum = struct.unpack_from("<H", data, 56)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        if p_type != 1:  # PT_LOAD
            continue
        p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = struct.unpack_from("<QQQQQQ", data, off + 8)
        segs.append((p_vaddr, p_vaddr + p_filesz, p_offset))
    return data, segs

def read_va(data: bytes, segs, va: int, size: int) -> bytes:
    for start, end, off in segs:
        if start <= va and va + size <= end:
            return data[off + va - start: off + va - start + size]
    raise ValueError(f"VA tidak termap: {va:#x}")

def main():
    binary = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("chall")
    if not binary.exists():
        binary = Path("chall.dec")
    if not binary.exists():
        raise SystemExit("binary chall/chall.dec tidak ditemukan")

    data, segs = load_elf(binary)
    tables = b"".join([
        read_va(data, segs, SR_VA, SIZES["sr"]),
        read_va(data, segs, FLAG_CT_VA, SIZES["flag_ct"]),
        read_va(data, segs, WB_TII_VA, SIZES["tii"]),
        read_va(data, segs, WB_TIII_VA, SIZES["tiii"]),
        read_va(data, segs, WB_XOR_VA, SIZES["xor"]),
        read_va(data, segs, WB_TV_VA, SIZES["tv"]),
    ])

    work = Path.cwd()
    table_path = work / ".lumaes_tables.bin"
    c_path = work / ".lumaes_helper.c"
    exe_path = work / ".lumaes_helper"
    table_path.write_bytes(tables)
    c_path.write_text(C_HELPER)

    try:
        subprocess.run(["gcc", "-O3", str(c_path), "-o", str(exe_path)], check=True)
    except FileNotFoundError:
        raise SystemExit("gcc tidak ditemukan; install gcc atau compile helper C secara manual")

    out = subprocess.check_output([str(exe_path), str(table_path)])
    flag = out.decode("ascii", "strict").strip()
    print(f"<FLAG>{flag}</FLAG>")

if __name__ == "__main__":
    main()

